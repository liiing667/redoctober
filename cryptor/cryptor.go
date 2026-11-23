// Package cryptor encrypts and decrypts files using the Red October
// vault and key cache.
//
// Copyright (c) 2013 CloudFlare, Inc.
package cryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/cloudflare/redoctober/config"
	"github.com/cloudflare/redoctober/keycache"
	"github.com/cloudflare/redoctober/msp"
	"github.com/cloudflare/redoctober/padding"
	"github.com/cloudflare/redoctober/passvault"
	"github.com/cloudflare/redoctober/persist"
	"github.com/cloudflare/redoctober/symcrypt"
)

const (
	DEFAULT_VERSION = 1
)

// reEncryptMutex serialises re-encryption operations.  A re-encryption
// consumes delegated key uses while it unwraps the source key; keeping that
// work atomic also prevents two concurrent rewraps from racing on the same
// delegated key.
var reEncryptMutex sync.Mutex

type Cryptor struct {
	records *passvault.Records
	cache   *keycache.Cache
	persist persist.Store
}

func New(records *passvault.Records, cache *keycache.Cache, config *config.Config) (*Cryptor, error) {
	if cache == nil {
		c := keycache.NewCache()
		cache = &c
	}

	store, err := persist.New(config.Delegations)
	if err != nil {
		return nil, err
	}

	c := &Cryptor{
		records: records,
		cache:   cache,
		persist: store,
	}
	return c, nil
}

// AccessStructure represents different possible access structures for
// encrypted data.  If len(Names) > 0, then at least 2 of the users in the list
// must be delegated to decrypt.  If len(LeftNames) > 0 & len(RightNames) > 0,
// then at least one from each list must be delegated (if the same user is in
// both, then he can decrypt it alone).  If a predicate is present, it must be
// satisfied to decrypt.
type AccessStructure struct {
	Minimum int
	Names   []string

	LeftNames  []string
	RightNames []string

	Predicate string
}

// Implements msp.UserDatabase
type UserDatabase struct {
	names *[]string

	records *passvault.Records
	cache   *keycache.Cache

	user     string
	labels   []string
	keySet   map[string]SingleWrappedKey
	shareSet map[string][][]byte
}

func (u UserDatabase) ValidUser(name string) bool {
	_, ok := u.records.GetRecord(name)
	return ok
}

func (u UserDatabase) CanGetShare(name string) bool {
	_, _, ok1 := u.cache.MatchUser(name, u.user, u.labels)
	_, ok2 := u.shareSet[name]
	_, ok3 := u.keySet[name]

	return ok1 && ok2 && ok3
}

func (u UserDatabase) GetShare(name string) ([][]byte, error) {
	*u.names = append(*u.names, name)

	return u.cache.DecryptShares(
		u.shareSet[name],
		name,
		u.user,
		u.labels,
		u.keySet[name].Key,
	)
}

// MultiWrappedKey is a structure containing a 16-byte key encrypted
// once for each of the keys corresponding to the names of the users
// in Name in order.
type MultiWrappedKey struct {
	Name []string
	Key  []byte
}

// SingleWrappedKey is a structure containing a 16-byte key encrypted
// by an RSA or EC key.
type SingleWrappedKey struct {
	Key    []byte
	aesKey []byte
}

// EncryptedData is the format for encrypted data containing all the
// keys necessary to decrypt it when delegated.
type EncryptedData struct {
	Version int
	VaultId int      `json:",omitempty"`
	Labels  []string `json:",omitempty"`
	// Usages list the endpoints which may use this data
	// If empty, only decryption in permitted
	Usages      []string                    `json:",omitempty"`
	Predicate   string                      `json:",omitempty"`
	Minimum     int                         `json:",omitempty"`
	Owners      []string                    `json:",omitempty"`
	LeftOwners  []string                    `json:",omitempty"`
	RightOwners []string                    `json:",omitempty"`
	KeySet      []MultiWrappedKey           `json:",omitempty"`
	KeySetRSA   map[string]SingleWrappedKey `json:",omitempty"`
	ShareSet    map[string][][]byte         `json:",omitempty"`
	IV          []byte                      `json:",omitempty"`
	Data        []byte
	Signature   []byte
}

type pair struct {
	name string
	key  []byte
}

type mwkSlice []MultiWrappedKey
type swkSlice []pair

func (s mwkSlice) Len() int      { return len(s) }
func (s mwkSlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s mwkSlice) Less(i, j int) bool { // Alphabetic order
	var shorter = i
	if len(s[i].Name) > len(s[j].Name) {
		shorter = j
	}

	for index := range s[shorter].Name {
		if s[i].Name[index] != s[j].Name[index] {
			return s[i].Name[index] < s[j].Name[index]
		}
	}

	return false
}

func (s swkSlice) Len() int           { return len(s) }
func (s swkSlice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s swkSlice) Less(i, j int) bool { return s[i].name < s[j].name }

// computeHmac computes the signature of the encrypted data structure
// the signature takes into account every element of the EncryptedData
// structure, with all keys sorted alphabetically by name
func (encrypted *EncryptedData) computeHmac(key []byte) []byte {
	mac := hmac.New(sha1.New, key)

	// Sort copies of the key sets, labels, and usages.  computeHmac must not
	// modify the EncryptedData: callers use the same parsed source snapshot
	// for identity, access structure, and output.
	mwks := mwkSlice(append([]MultiWrappedKey(nil), encrypted.KeySet...))
	sort.Sort(mwks)

	// sort the singly-wrapped keys
	var swks swkSlice
	for name, val := range encrypted.KeySetRSA {
		swks = append(swks, pair{name, val.Key})
	}
	sort.Sort(&swks)

	// sort the labels and usages
	labels := append([]string(nil), encrypted.Labels...)
	usages := append([]string(nil), encrypted.Usages...)
	sort.Strings(labels)
	sort.Strings(usages)

	// start hashing
	mac.Write([]byte(strconv.Itoa(encrypted.Version)))
	mac.Write([]byte(strconv.Itoa(encrypted.VaultId)))

	// hash the multi-wrapped keys
	for _, mwk := range mwks {
		for _, name := range mwk.Name {
			mac.Write([]byte(name))
		}
		mac.Write(mwk.Key)
	}

	// hash the single-wrapped keys
	for index := range swks {
		mac.Write([]byte(swks[index].name))
		mac.Write(swks[index].key)
	}

	// hash the IV and data
	mac.Write(encrypted.IV)
	mac.Write(encrypted.Data)

	// hash the labels
	for _, label := range labels {
		mac.Write([]byte(label))
	}

	// hash the usages
	for _, usage := range usages {
		mac.Write([]byte(usage))
	}

	// Hash the explicit access structure metadata.  These fields are absent
	// from legacy ciphertexts, so their zero values preserve the historical
	// signature while still binding new ciphertexts to their access policy.
	if encrypted.Minimum != 0 {
		mac.Write([]byte(strconv.Itoa(encrypted.Minimum)))
	}
	owners := append([]string(nil), encrypted.Owners...)
	leftOwners := append([]string(nil), encrypted.LeftOwners...)
	rightOwners := append([]string(nil), encrypted.RightOwners...)
	sort.Strings(owners)
	sort.Strings(leftOwners)
	sort.Strings(rightOwners)
	for _, name := range owners {
		mac.Write([]byte(name))
	}
	for _, name := range leftOwners {
		mac.Write([]byte(name))
	}
	for _, name := range rightOwners {
		mac.Write([]byte(name))
	}

	return mac.Sum(nil)
}

func (encrypted *EncryptedData) lock(key []byte) (err error) {
	payload, err := json.Marshal(encrypted)
	if err != nil {
		return
	}

	mac := hmac.New(sha1.New, key)
	mac.Write(payload)
	sig := mac.Sum(nil)

	*encrypted = EncryptedData{
		Version:   -1,
		Data:      payload,
		Signature: sig,
	}

	return
}

func (encrypted *EncryptedData) unlock(key []byte) (err error) {
	if encrypted.Version != -1 {
		return
	}

	mac := hmac.New(sha1.New, key)
	mac.Write(encrypted.Data)
	sig := mac.Sum(nil)

	if !hmac.Equal(encrypted.Signature, sig) {
		err = errors.New("Signature mismatch")
		return
	}

	return json.Unmarshal(encrypted.Data, encrypted)
}

// rewrapGenerateRandomKey generates a fresh intermediary key for name and wraps it
// with name's public key.
func rewrapGenerateRandomKey(records *passvault.Records, name string) (singleWrappedKey SingleWrappedKey, err error) {
	rec, ok := records.GetRecord(name)
	if !ok {
		err = errors.New("Missing user on disk")
		return
	}

	if singleWrappedKey.aesKey, err = symcrypt.MakeRandom(16); err != nil {
		return
	}

	if singleWrappedKey.Key, err = rec.EncryptKey(singleWrappedKey.aesKey); err != nil {
		return
	}

	return
}

// rewrapEncryptClearKey applies the intermediary AES keys named in keyNames to the
// clear key.  The order is the encryption order; DecryptKey applies the same
// names in the opposite order.
func rewrapEncryptClearKey(keySetRSA map[string]SingleWrappedKey, keyNames []string, clearKey []byte) (keyBytes []byte, err error) {
	if len(clearKey) != 16 {
		return nil, errors.New("Invalid key size")
	}

	keyBytes = make([]byte, len(clearKey))
	copy(keyBytes, clearKey)
	for _, keyName := range keyNames {
		wrappedKey, ok := keySetRSA[keyName]
		if !ok {
			return nil, fmt.Errorf("Missing wrapped key for user '%s'", keyName)
		}

		var keyCrypt cipher.Block
		keyCrypt, err = aes.NewCipher(wrappedKey.aesKey)
		if err != nil {
			return nil, err
		}

		keyCrypt.Encrypt(keyBytes, keyBytes)
	}

	return
}

// validateAccessStructure checks the parts of an access structure that can be
// checked without touching the vault or key cache.  It lets re-encryption
// reject an invalid destination before consuming delegated key uses.
func validateAccessStructure(access AccessStructure) error {
	if len(access.Names) > 0 && access.Minimum > 0 {
		if access.Minimum > 2 {
			return errors.New("Encryption to a list of owners with minimum > 2 is not implemented")
		}
		if access.Minimum > len(access.Names) {
			return errors.New("Minimum exceeds the number of owners")
		}
		return nil
	}
	if len(access.LeftNames) > 0 && len(access.RightNames) > 0 {
		return nil
	}
	if len(access.Predicate) > 0 {
		_, err := msp.StringToMSP(access.Predicate)
		return err
	}
	return errors.New("Invalid access structure.")
}

// wrapKey encrypts the clear key according to an access structure.
func (encrypted *EncryptedData) wrapKey(records *passvault.Records, clearKey []byte, access AccessStructure) (err error) {
	if err = validateAccessStructure(access); err != nil {
		return err
	}

	// Reset all access metadata and wrapped-key material so a partially
	// initialised output can never retain stale access information.
	encrypted.Minimum = 0
	encrypted.Owners = nil
	encrypted.LeftOwners = nil
	encrypted.RightOwners = nil
	encrypted.Predicate = ""
	encrypted.KeySet = nil
	encrypted.KeySetRSA = nil
	encrypted.ShareSet = nil

	if len(access.Names) > 0 && access.Minimum > 0 {
		// Generate a random AES key for each user and RSA/ECIES encrypt it
		encrypted.KeySetRSA = make(map[string]SingleWrappedKey)
		encrypted.Minimum = access.Minimum
		encrypted.Owners = rewrapCloneStrings(access.Names)

		for _, name := range access.Names {
			encrypted.KeySetRSA[name], err = rewrapGenerateRandomKey(records, name)
			if err != nil {
				return err
			}

			if access.Minimum == 1 {
				keyBytes, err := rewrapEncryptClearKey(encrypted.KeySetRSA, []string{name}, clearKey)
				if err != nil {
					return err
				}

				encrypted.KeySet = append(encrypted.KeySet, MultiWrappedKey{
					Name: []string{name},
					Key:  keyBytes,
				})
			}
		}

		if access.Minimum == 2 {
			for i := 0; i < len(access.Names); i++ {
				for j := i + 1; j < len(access.Names); j++ {
					keyBytes, err := rewrapEncryptClearKey(encrypted.KeySetRSA, []string{access.Names[j], access.Names[i]}, clearKey)
					if err != nil {
						return err
					}

					out := MultiWrappedKey{
						Name: []string{access.Names[i], access.Names[j]},
						Key:  keyBytes,
					}

					encrypted.KeySet = append(encrypted.KeySet, out)
				}
			}
		}
	} else if len(access.LeftNames) > 0 && len(access.RightNames) > 0 {
		// Generate a random AES key for each user and RSA/ECIES encrypt it
		encrypted.KeySetRSA = make(map[string]SingleWrappedKey)
		encrypted.LeftOwners = rewrapCloneStrings(access.LeftNames)
		encrypted.RightOwners = rewrapCloneStrings(access.RightNames)

		for _, name := range access.LeftNames {
			encrypted.KeySetRSA[name], err = rewrapGenerateRandomKey(records, name)
			if err != nil {
				return err
			}
		}

		for _, name := range access.RightNames {
			encrypted.KeySetRSA[name], err = rewrapGenerateRandomKey(records, name)
			if err != nil {
				return err
			}
		}

		// encrypt file key with every combination of one left key and one right key
		encrypted.KeySet = make([]MultiWrappedKey, 0)

		for _, leftName := range access.LeftNames {
			for _, rightName := range access.RightNames {
				if leftName == rightName {
					continue
				}

				keyBytes, err := rewrapEncryptClearKey(encrypted.KeySetRSA, []string{rightName, leftName}, clearKey)
				if err != nil {
					return err
				}

				out := MultiWrappedKey{
					Name: []string{leftName, rightName},
					Key:  keyBytes,
				}

				encrypted.KeySet = append(encrypted.KeySet, out)
			}
		}
	} else if len(access.Predicate) > 0 {
		encrypted.KeySetRSA = make(map[string]SingleWrappedKey)

		sss, err := msp.StringToMSP(access.Predicate)
		if err != nil {
			return err
		}

		db := UserDatabase{records: records}
		shareSet, err := sss.DistributeShares(clearKey, &db)
		if err != nil {
			return err
		}

		for name := range shareSet {
			encrypted.KeySetRSA[name], err = rewrapGenerateRandomKey(records, name)
			if err != nil {
				return err
			}
			crypt, err := aes.NewCipher(encrypted.KeySetRSA[name].aesKey)
			if err != nil {
				return err
			}

			for i := range shareSet[name] {
				tmp := make([]byte, 16)
				crypt.Encrypt(tmp, shareSet[name][i])
				shareSet[name][i] = tmp
			}
		}

		encrypted.ShareSet = shareSet
		encrypted.Predicate = access.Predicate
	} else {
		return errors.New("Invalid access structure.")
	}

	return nil
}

// unwrapKey decrypts first key in keys whose encryption keys are in keycache
func (encrypted *EncryptedData) unwrapKey(cache *keycache.Cache, user string) (unwrappedKey []byte, names []string, err error) {
	var (
		decryptErr error
		fullMatch  bool = false
		nameSet         = map[string]bool{}
	)

	if len(encrypted.Predicate) == 0 {
		for _, mwKey := range encrypted.KeySet {
			// validate the size of the keys
			if len(mwKey.Key) != 16 {
				err = errors.New("Invalid Input")
			}

			if err != nil {
				return nil, nil, err
			}

			// loop through users to see if they are all delegated
			fullMatch = true
			for _, mwName := range mwKey.Name {
				if valid := cache.Valid(mwName, user, encrypted.Labels); !valid {
					fullMatch = false
					break
				}
				nameSet[mwName] = true
			}

			// if the keys are delegated, decrypt the mwKey with them
			if fullMatch == true {
				tmpKeyValue := mwKey.Key
				for _, mwName := range mwKey.Name {
					pubEncrypted := encrypted.KeySetRSA[mwName]
					if tmpKeyValue, decryptErr = cache.DecryptKey(tmpKeyValue, mwName, user, encrypted.Labels, pubEncrypted.Key); decryptErr != nil {
						break
					}
				}
				unwrappedKey = tmpKeyValue
				break
			}
		}

		if !fullMatch {
			err = ErrNotEnoughDelegations
			return
		}

		if decryptErr != nil {
			err = errors.New("Failed to decrypt with all keys in keyset")
			return
		}

		names = make([]string, 0, len(nameSet))
		for name := range nameSet {
			names = append(names, name)
		}
		return
	}
	var sss msp.MSP
	sss, err = msp.StringToMSP(encrypted.Predicate)
	if err != nil {
		return nil, nil, err
	}

	db := UserDatabase{
		names:    &names,
		cache:    cache,
		user:     user,
		labels:   encrypted.Labels,
		keySet:   encrypted.KeySetRSA,
		shareSet: encrypted.ShareSet,
	}
	unwrappedKey, err = sss.RecoverSecret(&db)

	return
}

// rewrapCloneStrings copies a string slice while preserving the distinction
// between a nil slice (field omitted) and an explicitly empty slice.
func rewrapCloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

// rewrapCloneBytes copies a byte slice.
func rewrapCloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

// unlockAndVerify parses in, unlocks it if necessary, and verifies that it
// belongs to the active vault and has a valid signature.  The returned
// EncryptedData is the single source snapshot used by callers.
func (c *Cryptor) unlockAndVerify(in []byte) (encrypted EncryptedData, secure bool, err error) {
	if err = json.Unmarshal(in, &encrypted); err != nil {
		return
	}
	if encrypted.Version != DEFAULT_VERSION && encrypted.Version != -1 {
		err = errors.New("Unknown version")
		return
	}

	secure = encrypted.Version == -1

	hmacKey, err := c.records.GetHMACKey()
	if err != nil {
		return encrypted, secure, err
	}

	if err = encrypted.unlock(hmacKey); err != nil {
		return encrypted, secure, err
	}

	// make sure file was encrypted with the active vault
	vaultId, err := c.records.GetVaultID()
	if err != nil {
		return encrypted, secure, err
	}
	if encrypted.VaultId != vaultId {
		return encrypted, secure, errors.New("Wrong vault")
	}

	// compute HMAC
	expectedMAC := encrypted.computeHmac(hmacKey)
	if !hmac.Equal(encrypted.Signature, expectedMAC) {
		return encrypted, secure, errors.New("Signature mismatch")
	}

	return encrypted, secure, nil
}

// Encrypt encrypts data with the keys associated with names. This
// requires a minimum of min keys to decrypt.  NOTE: as currently
// implemented, the maximum value for min is 2.
func (c *Cryptor) Encrypt(in []byte, labels []string, usages []string, access AccessStructure) (resp []byte, err error) {
	if err = validateAccessStructure(access); err != nil {
		return nil, err
	}

	var encrypted EncryptedData
	encrypted.Version = DEFAULT_VERSION
	if encrypted.VaultId, err = c.records.GetVaultID(); err != nil {
		return
	}

	// Generate random IV and encryption key
	encrypted.IV, err = symcrypt.MakeRandom(16)
	if err != nil {
		return
	}

	clearKey, err := symcrypt.MakeRandom(16)
	if err != nil {
		return
	}

	err = encrypted.wrapKey(c.records, clearKey, access)
	if err != nil {
		return
	}

	// encrypt file with clear key
	aesCrypt, err := aes.NewCipher(clearKey)
	if err != nil {
		return
	}

	clearFile := padding.AddPadding(in)

	encryptedFile := make([]byte, len(clearFile))
	aesCBC := cipher.NewCBCEncrypter(aesCrypt, encrypted.IV)
	aesCBC.CryptBlocks(encryptedFile, clearFile)

	encrypted.Data = encryptedFile
	encrypted.Labels = rewrapCloneStrings(labels)
	encrypted.Usages = rewrapCloneStrings(usages)

	hmacKey, err := c.records.GetHMACKey()
	if err != nil {
		return
	}
	encrypted.Signature = encrypted.computeHmac(hmacKey)
	encrypted.lock(hmacKey)

	return json.Marshal(encrypted)
}

// ReEncrypt re-wraps an existing ciphertext under a fresh set of
// intermediary keys.  The source data key, IV, and ciphertext are kept
// unchanged; only the wrapping keys and, optionally, the access structure,
// labels, and usages are replaced.
//
// A nil access, labels, or usages means "keep the source value".  A
// non-nil value replaces the corresponding source value.  All work is
// staged in local variables and the result is returned only after the whole
// output has been wrapped, signed, and serialised.  If anything fails, the
// delegated key usage consumed while unwrapping the source is rolled back.
func (c *Cryptor) ReEncrypt(in []byte, user string, access *AccessStructure, labels, usages []string) (out []byte, err error) {
	reEncryptMutex.Lock()
	defer reEncryptMutex.Unlock()

	source, secure, err := c.unlockAndVerify(in)
	if err != nil {
		return nil, err
	}
	if !secure {
		return nil, errors.New("decryption's secure bit is false")
	}

	if labels == nil {
		labels = rewrapCloneStrings(source.Labels)
	}
	if usages == nil {
		usages = rewrapCloneStrings(source.Usages)
	}

	if access != nil {
		destination := *access
		if len(destination.Names) > 0 && destination.Minimum <= 0 {
			// If the caller supplied owners but omitted the threshold,
			// retain the threshold of the source owner structure.  If the
			// source used a predicate, fall back to the conventional
			// one-owner threshold for a single owner and two for a larger
			// owner set.
			destination.Minimum = sourceOwnerMinimum(source)
			if destination.Minimum <= 0 {
				if len(destination.Names) == 1 {
					destination.Minimum = 1
				} else {
					destination.Minimum = 2
				}
			}
		}
		access = &destination
	}

	// Reject an invalid destination before consuming delegated key uses.
	if access != nil {
		if err = validateAccessStructure(*access); err != nil {
			return nil, err
		}
	} else if len(source.Predicate) == 0 && len(source.KeySet) == 0 && len(source.KeySetRSA) == 0 {
		return nil, errors.New("Invalid access structure.")
	}

	cacheSnapshot := c.cache.Snapshot()
	rollback := func() {
		c.cache.Rollback(cacheSnapshot)
	}

	clearKey, _, err := source.unwrapKey(c.cache, user)
	if err != nil {
		rollback()
		return nil, err
	}
	if len(clearKey) != 16 {
		rollback()
		return nil, errors.New("Invalid key size")
	}

	rewrapped := EncryptedData{
		Version: DEFAULT_VERSION,
		VaultId: source.VaultId,
		Labels:  rewrapCloneStrings(labels),
		Usages:  rewrapCloneStrings(usages),
		IV:      rewrapCloneBytes(source.IV),
		Data:    rewrapCloneBytes(source.Data),
	}

	switch {
	case access != nil:
		err = rewrapped.wrapKey(c.records, clearKey, *access)
	case len(source.Predicate) > 0:
		err = rewrapped.wrapKey(c.records, clearKey, AccessStructure{Predicate: source.Predicate})
		if err == nil {
			copyAccessMetadata(&rewrapped, &source)
		}
	default:
		err = rewrapOwnerKey(c.records, &rewrapped, clearKey, &source)
	}
	if err != nil {
		rollback()
		return nil, err
	}

	hmacKey, err := c.records.GetHMACKey()
	if err != nil {
		rollback()
		return nil, err
	}
	rewrapped.Signature = rewrapped.computeHmac(hmacKey)
	rewrapped.lock(hmacKey)

	out, err = json.Marshal(rewrapped)
	if err != nil {
		rollback()
		return nil, err
	}
	return out, nil
}

// copyAccessMetadata copies the explicit access metadata from source to dst.
// The KeySet/ShareSet themselves are regenerated separately.
func copyAccessMetadata(dst, source *EncryptedData) {
	dst.Minimum = source.Minimum
	dst.Owners = rewrapCloneStrings(source.Owners)
	dst.LeftOwners = rewrapCloneStrings(source.LeftOwners)
	dst.RightOwners = rewrapCloneStrings(source.RightOwners)
}

// sourceOwnerMinimum recovers the threshold used by an owner-based source
// ciphertext.  Predicate and malformed structures return zero.
func sourceOwnerMinimum(source EncryptedData) int {
	if len(source.Predicate) > 0 {
		return 0
	}
	if source.Minimum > 0 && len(source.Owners) > 0 {
		return source.Minimum
	}
	if len(source.KeySet) == 0 {
		if len(source.KeySetRSA) > 0 {
			return 1
		}
		return 0
	}

	for _, mwk := range source.KeySet {
		if len(mwk.Name) > 1 {
			return 2
		}
	}
	return 1
}

// Rewrap is an alias for ReEncrypt.
func (c *Cryptor) Rewrap(in []byte, user string, access *AccessStructure, labels, usages []string) ([]byte, error) {
	return c.ReEncrypt(in, user, access, labels, usages)
}

// ReWrap is an alias for ReEncrypt.
func (c *Cryptor) ReWrap(in []byte, user string, access *AccessStructure, labels, usages []string) ([]byte, error) {
	return c.ReEncrypt(in, user, access, labels, usages)
}

// rewrapOwnerKey regenerates the intermediary keys for an owner-based
// ciphertext while preserving the exact combinatorial owner structure.  In
// particular, this keeps legacy KeySet layouts (single owners, minimum-two
// owner sets, and left/right owner sets) intact instead of guessing which
// access-structure mode originally produced them.
func rewrapOwnerKey(records *passvault.Records, encrypted *EncryptedData, clearKey []byte, source *EncryptedData) (err error) {
	encrypted.KeySetRSA = make(map[string]SingleWrappedKey)
	encrypted.KeySet = make([]MultiWrappedKey, 0, len(source.KeySet))
	copyAccessMetadata(encrypted, source)

	// Generate fresh intermediary keys for every name present in the source.
	addName := func(name string) error {
		if _, ok := encrypted.KeySetRSA[name]; ok {
			return nil
		}
		wrapped, err := rewrapGenerateRandomKey(records, name)
		if err != nil {
			return err
		}
		encrypted.KeySetRSA[name] = wrapped
		return nil
	}

	for _, mwk := range source.KeySet {
		for _, name := range mwk.Name {
			if err := addName(name); err != nil {
				return err
			}
		}
	}
	for name := range source.KeySetRSA {
		if _, ok := encrypted.KeySetRSA[name]; ok {
			continue
		}
		// KeySetRSA can contain entries that are no longer referenced by
		// KeySet.  They do not affect the owner structure, so ignore stale
		// entries rather than failing an otherwise valid rewrap.
		if _, ok := records.GetRecord(name); !ok {
			continue
		}
		if err := addName(name); err != nil {
			return err
		}
	}

	if len(source.KeySet) == 0 {
		// A KeySetRSA-only ciphertext has no combinatorial structure to
		// preserve; treat every name as a single-owner entry.
		names := make([]string, 0, len(encrypted.KeySetRSA))
		for name := range encrypted.KeySetRSA {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			keyBytes, err := rewrapEncryptClearKey(encrypted.KeySetRSA, []string{name}, clearKey)
			if err != nil {
				return err
			}
			encrypted.KeySet = append(encrypted.KeySet, MultiWrappedKey{
				Name: []string{name},
				Key:  keyBytes,
			})
		}
		return nil
	}

	for _, sourceMWK := range source.KeySet {
		if len(sourceMWK.Name) == 0 {
			return errors.New("Invalid owner structure")
		}

		// A MultiWrappedKey lists the users in the order used for
		// decryption.  The wrapping was applied in the reverse order.
		encryptNames := make([]string, len(sourceMWK.Name))
		for i, name := range sourceMWK.Name {
			encryptNames[len(sourceMWK.Name)-1-i] = name
		}

		keyBytes, err := rewrapEncryptClearKey(encrypted.KeySetRSA, encryptNames, clearKey)
		if err != nil {
			return err
		}
		encrypted.KeySet = append(encrypted.KeySet, MultiWrappedKey{
			Name: rewrapCloneStrings(sourceMWK.Name),
			Key:  keyBytes,
		})
	}

	return nil
}

// Decrypt decrypts a file using the keys in the key cache.
func (c *Cryptor) Decrypt(in []byte, user string) (resp []byte, labels, names []string, usages []string, secure bool, err error) {
	return c.decrypt(c.cache, in, user)
}

func (c *Cryptor) decrypt(cache *keycache.Cache, in []byte, user string) (resp []byte, labels, names []string, usages []string, secure bool, err error) {
	encrypted, secure, err := c.unlockAndVerify(in)
	if err != nil {
		return
	}

	// decrypt file key with delegate keys
	var unwrappedKey = make([]byte, 16)
	unwrappedKey, names, err = encrypted.unwrapKey(cache, user)
	if err != nil {
		return
	}

	aesCrypt, err := aes.NewCipher(unwrappedKey)
	if err != nil {
		return
	}
	clearData := make([]byte, len(encrypted.Data))
	aesCBC := cipher.NewCBCDecrypter(aesCrypt, encrypted.IV)

	// decrypt contents of file
	aesCBC.CryptBlocks(clearData, encrypted.Data)

	resp, err = padding.RemovePadding(clearData)
	labels = encrypted.Labels
	usages = encrypted.Usages
	return
}

// GetOwners returns the list of users that can delegate their passwords
// to decrypt the given encrypted secret.
func (c *Cryptor) GetOwners(in []byte) (names, labels []string, predicate string, err error) {
	encrypted, _, err := c.unlockAndVerify(in)
	if err != nil {
		return
	}

	addedNames := make(map[string]bool)
	addName := func(name string) {
		if !addedNames[name] {
			names = append(names, name)
			addedNames[name] = true
		}
	}

	if len(encrypted.Predicate) == 0 {
		// New ciphertexts carry the source access structure explicitly.
		for _, name := range encrypted.Owners {
			addName(name)
		}
		for _, name := range encrypted.LeftOwners {
			addName(name)
		}
		for _, name := range encrypted.RightOwners {
			addName(name)
		}
	}

	for _, mwKey := range encrypted.KeySet { // names from the combinatorial method
		for _, mwName := range mwKey.Name {
			addName(mwName)
		}
	}

	for name := range encrypted.ShareSet { // names from the secret splitting method
		addName(name)
	}
	sort.Strings(names)
	predicate = encrypted.Predicate
	labels = rewrapCloneStrings(encrypted.Labels)

	return
}

// LiveSummary returns a list of the users currently delegated.
func (c *Cryptor) LiveSummary() map[string]keycache.ActiveUser {
	return c.cache.GetSummary()
}

// Refresh purges all expired or fully-used delegations in the
// crypto's key cache. It returns an error if the delegations
// should have been stored, but couldn't be.
func (c *Cryptor) Refresh() error {
	n := c.cache.Refresh()
	if n != 0 {
		return c.store()
	}
	return nil
}

// Flush removes all delegations.
func (c *Cryptor) Flush() error {
	if c.cache.Flush() {
		return c.store()
	}
	return nil
}

// Delegate attempts to decrypt a key for the specified user and add
// the key to the key cache.
func (c *Cryptor) Delegate(record passvault.PasswordRecord, name, password string, users, labels []string, uses int, slot, durationString string) (err error) {
	err = c.cache.AddKeyFromRecord(record, name, password, users, labels, uses, slot, durationString)
	if err != nil {
		return err
	}

	return c.store()
}

// DelegateStatus will return a list of admins who have delegated to a particular user, for a particular label.
// This is useful information to have when determining the status of an order and conveying order progress.
func (c *Cryptor) DelegateStatus(name string, labels, admins []string) (adminsDelegated []string, hasDelegated int) {
	return c.cache.DelegateStatus(name, labels, admins)
}

// store serialises the key cache, encrypts it, and writes it to disk.
func (c *Cryptor) store() error {
	// If the store isn't currently active, we shouldn't attempt
	// to persist the store.
	st := c.persist.Status()
	if st.State != persist.Active {
		return nil
	}

	cache, err := json.Marshal(c.cache.GetSummary())
	if err != nil {
		return err
	}

	access := AccessStructure{
		Names:     c.persist.Users(),
		Predicate: c.persist.Policy(),
	}

	cache, err = c.Encrypt(cache, persist.Labels, persist.Usages, access)
	if err != nil {
		return err
	}

	return c.persist.Store(cache)
}

// ErrRestoreDelegations is a sentinal value returned when more
// delegations are needed for the restore to continue.
var ErrRestoreDelegations = errors.New("cryptor: need more delegations")

// ErrNotEnoughDelegations is a error returned by Decrypt.
var ErrNotEnoughDelegations = errors.New("need more delegated keys")

// Restore delegates the named user to the persistence key cache. If
// enough delegations are present to restore the cache, the current
// Red October key cache is replaced with the persisted one.
func (c *Cryptor) Restore(name, password string, uses int, slot, durationString string) error {
	// If the persistence store is already active, don't proceed.
	if st := c.persist.Status(); st != nil && st.State == persist.Active {
		return nil
	}

	record, ok := c.records.GetRecord(name)
	if !ok {
		return errors.New("Missing user on disk")
	}

	err := c.persist.Delegate(record, name, password, c.persist.Users(), persist.Labels, uses, slot, durationString)
	if err != nil {
		return err
	}

	// A failure to decrypt isn't a restore error, it (most often)
	// just means there aren't enough delegations yet; the
	// sentinal value ErrRestoreDelegations is returned to
	// indicate this. However, the error
	cache, _, _, names, _, err := c.decrypt(c.persist.Cache(), c.persist.Blob(), name)
	if err != nil {
		if err == msp.ErrNotEnoughShares {
			return ErrRestoreDelegations
		}
		return err
	}

	log.Printf("cryptor.restore success: names=%s", strings.Join(names, ","))

	var uk map[string]keycache.ActiveUser
	err = json.Unmarshal(cache, &uk)
	if err != nil {
		return err
	}

	rcache := keycache.NewFrom(uk)
	err = rcache.Restore()
	if err != nil {
		return err
	}

	c.cache = rcache
	c.persist.Persist()
	c.persist.Cache().Flush()
	return nil
}

// Status returns the status of the underlying persistence store.
func (c *Cryptor) Status() *persist.Status {
	return c.persist.Status()
}

// ResetPersisted clears any persisted delegations and returns the
// vault to an active delegation state if configured.
func (c *Cryptor) ResetPersisted() (*persist.Status, error) {
	err := c.persist.Purge()
	return c.persist.Status(), err
}
