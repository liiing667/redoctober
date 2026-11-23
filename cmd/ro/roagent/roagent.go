// Package roagent provides ROAgent, which implements the SSH agent interface,
// forwarding sign requests to a Red October server

package roagent

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"io"

	roclient "github.com/cloudflare/redoctober/client"
	"github.com/cloudflare/redoctober/core"
	"golang.org/x/crypto/ssh"
)

// errStaleSigner is returned when a signer handle no longer belongs to
// the agent's current keyring generation, e.g. after the key was
// removed, the agent was locked, or a previous signing attempt failed.
var errStaleSigner = errors.New("ro-ssh-agent: stale signer")

type ROAgent struct {
	locked     bool
	keyring    []*ROSigner
	generation uint64

	server   *roclient.RemoteServer
	username string
	password string
}

type ROSigner struct {
	pub        ssh.PublicKey
	encKey     []byte
	roagent    *ROAgent
	comment    string
	generation uint64
}

func (rosigner ROSigner) PublicKey() ssh.PublicKey {
	return rosigner.pub
}

func (rosigner ROSigner) Sign(rand io.Reader, msg []byte) (signature *ssh.Signature, err error) {
	agent := rosigner.roagent
	if agent == nil {
		return nil, errors.New("ro-ssh-agent: signer is not attached to an agent")
	}
	if agent.locked {
		return nil, errLocked
	}
	// A signer handle is only valid for the keyring generation it was
	// minted in. Locking the agent, removing the key, or a failed
	// signing attempt all bump the generation or evict the key, so a
	// stale handle can never be used to sign new requests.
	if rosigner.generation != agent.generation || !agent.hasSigner(rosigner.pub) {
		return nil, errStaleSigner
	}

	// Bind the to-be-signed blob, its digest, the expected signer
	// identity and the current delegation generation into the request
	// so the core can verify them before issuing a signature.
	tbsDigest := sha256.Sum256(msg)
	req := core.SSHSignWithRequest{
		Name:     rosigner.roagent.username,
		Password: rosigner.roagent.password,
		Data:     rosigner.encKey,
		TBSData:  msg,

		TBSDigest:  tbsDigest[:],
		Signer:     rosigner.pub.Marshal(),
		Generation: rosigner.generation,
	}

	resp, err := rosigner.roagent.server.SSHSignWith(req)
	if err != nil {
		// A failed attempt must not leave a usable signer behind:
		// evict the key so a retry cannot silently reuse stale state.
		agent.evict(rosigner.pub)
		return nil, err
	}
	if resp.Status != "ok" {
		agent.evict(rosigner.pub)
		return nil, errors.New("ro-ssh-agent: response status error: " + resp.Status)
	}

	var respMsg core.SSHSignatureWithDelegates
	err = json.Unmarshal(resp.Response, &respMsg)
	if err != nil {
		agent.evict(rosigner.pub)
		return nil, err
	}

	// Verify the issuance bindings on the response: the core must have
	// signed exactly the blob we asked for, with exactly the key we
	// asked it to use.
	if len(respMsg.TBSDigest) != 0 && !bytes.Equal(respMsg.TBSDigest, tbsDigest[:]) {
		agent.evict(rosigner.pub)
		return nil, errors.New("ro-ssh-agent: server signed a different TBS digest")
	}
	if respMsg.SignerFingerprint != "" && respMsg.SignerFingerprint != ssh.FingerprintSHA256(rosigner.pub) {
		agent.evict(rosigner.pub)
		return nil, errors.New("ro-ssh-agent: server signed with a different key")
	}

	sshSignature := ssh.Signature{
		Format: respMsg.SignatureFormat,
		Blob:   respMsg.Signature,
	}
	return &sshSignature, nil
}

// NewROAgent creates a new SSH agent which forwards signature requests to the
// provided remote server
func NewROAgent(server *roclient.RemoteServer, username, password string) *ROAgent {
	return &ROAgent{
		server:   server,
		username: username,
		password: password,
		keyring:  []*ROSigner{},
	}
}

// NewROSigner adds a new SSH identity to the ROAgent
func NewROSigner(pubKey ssh.PublicKey, encBytes []byte) *ROSigner {
	return &ROSigner{
		pub:    pubKey,
		encKey: encBytes,
	}
}

// RemoveAll empties ROAgent's keyring
func (roagent *ROAgent) RemoveAll() error {
	if roagent.locked {
		return errLocked
	}
	roagent.keyring = []*ROSigner{}
	roagent.generation++
	return nil
}

// Remove removes the first matching key from ROAgent's keyring
func (roagent *ROAgent) Remove(key ssh.PublicKey) error {
	if roagent.locked {
		return errLocked
	}
	wanted := key.Marshal()
	for i, rosigner := range roagent.keyring {
		if bytes.Equal(rosigner.PublicKey().Marshal(), wanted) {
			roagent.keyring = append(roagent.keyring[:i], roagent.keyring[i+1:]...)
			roagent.generation++
			log.Println("ro-ssh-agent: signer removed")
			return nil
		}
	}
	return errors.New("ro-ssh-agent: could not remove signer")
}

// hasSigner reports whether a signer for pub is currently on the keyring.
func (roagent *ROAgent) hasSigner(pub ssh.PublicKey) bool {
	wanted := pub.Marshal()
	for _, rosigner := range roagent.keyring {
		if bytes.Equal(rosigner.PublicKey().Marshal(), wanted) {
			return true
		}
	}
	return false
}

// evict removes every signer for pub from the keyring and bumps the
// keyring generation, invalidating any outstanding signer handles for
// the evicted key.
func (roagent *ROAgent) evict(pub ssh.PublicKey) {
	wanted := pub.Marshal()
	kept := make([]*ROSigner, 0, len(roagent.keyring))
	removed := false
	for _, rosigner := range roagent.keyring {
		if bytes.Equal(rosigner.PublicKey().Marshal(), wanted) {
			removed = true
			continue
		}
		kept = append(kept, rosigner)
	}
	if removed {
		roagent.keyring = kept
		roagent.generation++
		log.Println("ro-ssh-agent: signer evicted after failure")
	}
}

// Locks the ROAgent by removing the password
// TODO should this encrypt the password instead?
func (roagent *ROAgent) Lock(passphrase []byte) error {
	if roagent.locked {
		return errLocked
	}
	if len(passphrase) != len(roagent.password) || 1 != subtle.ConstantTimeCompare(passphrase, []byte(roagent.password)) {
		roagent.password = ""
		roagent.locked = true
		roagent.generation++
		return nil
	}
	return errors.New("ro-ssh-agent: could not lock the agent")
}

// Unlocks the ROAgent by changing the password
// FIXME ask papa RO if the password is correct
func (roagent *ROAgent) Unlock(passphrase []byte) error {
	if !roagent.locked {
		return errors.New("ro-ssh-agent: agent is not locked")
	}
	roagent.locked = false
	roagent.password = string(passphrase)
	return nil
}

// List returns the identities known to the agent.
func (roagent *ROAgent) List() ([]*Key, error) {
	if roagent.locked {
		// section 2.7: locked agents return empty.
		return nil, nil
	}

	list := make([]*Key, len(roagent.keyring))
	for i, rosigner := range roagent.keyring {
		list[i] = &Key{
			Format:  rosigner.PublicKey().Type(),
			Blob:    rosigner.PublicKey().Marshal(),
			Comment: roagent.username,
		}
	}
	return list, nil
}

// Adds a new encrypted key to ROAgent's keyring
func (roagent *ROAgent) Add(key AddedKey) error {
	if roagent.locked {
		return errLocked
	}

	rosigner := key.PrivateKey.(*ROSigner)
	rosigner.roagent = roagent
	rosigner.generation = roagent.generation
	roagent.keyring = append(roagent.keyring, rosigner)
	log.Println("new signer was added. Total:", len(roagent.keyring))
	return nil
}

// Sign returns a signature for the data.
func (roagent *ROAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	if roagent.locked {
		return nil, errLocked
	}

	wanted := key.Marshal()
	for _, rosigner := range roagent.keyring {
		if bytes.Equal(rosigner.PublicKey().Marshal(), wanted) {
			rosigner.roagent = roagent
			rosigner.generation = roagent.generation
			return rosigner.Sign(rand.Reader, data)
		}
	}
	return nil, errors.New("key not found on keyring")
}

// Signers returns signers for all the known keys.
func (roagent *ROAgent) Signers() ([]ssh.Signer, error) {
	if roagent.locked {
		return nil, errLocked
	}

	list := make([]ssh.Signer, len(roagent.keyring))
	for i, rosigner := range roagent.keyring {
		rosigner.roagent = roagent
		rosigner.generation = roagent.generation
		list[i] = ssh.Signer(rosigner)
	}
	return list, nil
}
