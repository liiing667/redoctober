// Package keycache provides the ability to hold active keys in memory
// for the Red October server.
//
// Copyright (c) 2013 CloudFlare, Inc.
package keycache

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/redoctober/ecdh"
	"github.com/cloudflare/redoctober/passvault"
)

// DelegateIndex is used to index the map of currently delegated keys.
// This is necessary to provide a way for a delegator to provide multiple
// delegations. It is also used to avoid the complexity of string parsing
// and enforcement of username and slot character requirements.
type DelegateIndex struct {
	Name string
	Slot string
}

// Usage holds the permissions of a delegated permission
type Usage struct {
	Uses   int       // Number of uses delegated
	Labels []string  // File labels allowed to decrypt
	Users  []string  // Set of users allows to decrypt
	Expiry time.Time // Expiration of usage
}

// ActiveUser holds the information about an actively delegated key.
type ActiveUser struct {
	Usage
	AltNames map[string]string
	Admin    bool
	Type     string
	Key      []byte

	// Generation is the identity generation of the delegator at the
	// time the delegation was created. A cached key is only valid
	// while its generation matches the record's current generation.
	Generation uint64

	rsaKey rsa.PrivateKey
	eccKey *ecdsa.PrivateKey
}

// Cache represents the current list of delegated keys in memory
type Cache struct {
	lock     *sync.Mutex
	UserKeys map[DelegateIndex]ActiveUser

	// generations records the current identity generation of every
	// user the cache knows about. An entry whose Generation differs
	// from the recorded one is stale and can never be used; an entry
	// for a user that has vanished from the registry (a deleted
	// identity) is stale as well.
	generations map[string]uint64
}

// matchesLabel returns true if this usage applies the user and label
// an empty array of Users indicates that all users are valid
func (usage Usage) matchesLabel(labels []string) bool {
	// if asset has no labels always match
	if len(labels) == 0 {
		return true
	}

	for _, validLabel := range usage.Labels {
		for _, label := range labels {
			if label == validLabel {
				return true
			}
		}
	}
	return false
}

// matches returns true if this usage applies the user and label
// an empty array of Users indicates that all users are valid
func (usage Usage) matches(user string, labels []string) bool {
	if !usage.matchesLabel(labels) {
		return false
	}
	// if usage lists no users, always match
	if len(usage.Users) == 0 {
		return true
	}
	for _, validUser := range usage.Users {
		if user == validUser {
			return true
		}
	}
	return false
}

// NewCache initalizes a new cache.
func NewCache() Cache {
	return Cache{
		UserKeys:    make(map[DelegateIndex]ActiveUser),
		generations: make(map[string]uint64),
		lock:        new(sync.Mutex),
	}
}

// currentGeneration reports the generation the cache currently holds
// for a user. The boolean is false when the user is unknown to the
// cache, which means no generation check can be applied.
func (cache *Cache) currentGeneration(name string) (uint64, bool) {
	gen, ok := cache.generations[name]
	return gen, ok
}

// generationValid reports whether a delegated key carrying gen for
// name still belongs to the user's current identity generation.
func (cache *Cache) generationValid(name string, gen uint64) bool {
	current, ok := cache.currentGeneration(name)
	if !ok {
		// No registry information: retain the legacy behaviour so
		// that caches which have never been synchronised keep
		// working. Production servers always synchronise the
		// registry during initialisation.
		return true
	}
	return current == gen
}

// SetGeneration records the current identity generation of a user and
// immediately retires every cached delegation for that user which was
// minted under an earlier generation. It returns the number of
// delegations removed.
func (cache *Cache) SetGeneration(name string, generation uint64) int {
	cache.lock.Lock()
	defer cache.lock.Unlock()

	cache.generations[name] = generation

	var removed int
	for d, active := range cache.UserKeys {
		if d.Name == name && active.Generation != generation {
			delete(cache.UserKeys, d)
			removed++
		}
	}
	return removed
}

// SyncGenerations reconciles the cache with the identity generations
// currently held by the vault. Delegations whose generation no longer
// matches are pruned, and delegations belonging to users that no
// longer exist are removed as well. It returns the number of
// delegations removed.
func (cache *Cache) SyncGenerations(current map[string]uint64) int {
	cache.lock.Lock()
	defer cache.lock.Unlock()

	// Replace the registry with the vault's authoritative view.
	cache.generations = make(map[string]uint64, len(current))
	for name, generation := range current {
		cache.generations[name] = generation
	}

	var removed int
	for d, active := range cache.UserKeys {
		generation, ok := current[d.Name]
		if !ok || generation != active.Generation {
			delete(cache.UserKeys, d)
			removed++
		}
	}
	return removed
}

// InvalidateUser retires every delegation currently held for name.
// The last known generation is kept in the registry so that stale
// entries restored later (for example from the persistence file)
// remain rejected.
func (cache *Cache) InvalidateUser(name string) int {
	cache.lock.Lock()
	defer cache.lock.Unlock()

	var removed int
	for d := range cache.UserKeys {
		if d.Name == name {
			delete(cache.UserKeys, d)
			removed++
		}
	}
	return removed
}

// NewFrom takes the output of GetSummary and returns a new keycache.
// The optional generations map holds the identity generations
// currently authoritative in the vault; restored entries that
// reference a retired generation, or a user which no longer exists,
// are dropped instead of being resurrected. An omitted or nil
// registry preserves the legacy behaviour.
func NewFrom(summary map[string]ActiveUser, generationSets ...map[string]uint64) *Cache {
	var generations map[string]uint64
	if len(generationSets) != 0 {
		generations = generationSets[0]
	}

	cache := &Cache{
		UserKeys:    make(map[DelegateIndex]ActiveUser),
		generations: make(map[string]uint64),
		lock:        new(sync.Mutex),
	}

	for name, generation := range generations {
		cache.generations[name] = generation
	}

	for di, user := range summary {
		diSplit := strings.SplitN(di, "-", 2)
		index := DelegateIndex{
			Name: diSplit[0],
		}

		if len(diSplit) == 2 {
			index.Slot = diSplit[1]
		}

		// Refuse to resurrect a reference whose identity
		// generation has been retired or whose user is gone.
		if current, ok := cache.generations[index.Name]; ok {
			if current != user.Generation {
				continue
			}
		} else if generations != nil {
			continue
		}
		cache.UserKeys[index] = user
	}

	return cache
}

// setUser takes an ActiveUser and adds it to the cache.
func (cache *Cache) setUser(in ActiveUser, name, slot string) {
	cache.lock.Lock()
	cache.UserKeys[DelegateIndex{Name: name, Slot: slot}] = in
	cache.lock.Unlock()
}

// Valid returns true if matching active user is present.
func (cache *Cache) Valid(name, user string, labels []string) (present bool) {
	for d, key := range cache.UserKeys {
		if d.Name != name {
			continue
		}
		if !cache.generationValid(d.Name, key.Generation) {
			continue
		}
		if key.Usage.matches(user, labels) {
			return true
		}
	}

	return false
}

// MatchUser returns the matching active user if present
// and a boolean to indicate its presence.
func (cache *Cache) MatchUser(name, user string, labels []string) (ActiveUser, string, bool) {
	var key ActiveUser
	for d, key := range cache.UserKeys {
		if d.Name != name {
			continue
		}
		if !cache.generationValid(d.Name, key.Generation) {
			continue
		}
		if key.Usage.matches(user, labels) {
			return key, d.Slot, true
		}
	}

	return key, "", false
}

// useKey decrements the counter on an active key
// for decryption or symmetric encryption
func (cache *Cache) useKey(name, user, slot string, labels []string) {
	if val, slot, present := cache.MatchUser(name, user, labels); present {
		val.Usage.Uses--
		if val.Usage.Uses <= 0 {
			delete(cache.UserKeys, DelegateIndex{name, slot})
		} else {
			cache.setUser(val, name, slot)
		}
	}
}

// GetSummary returns the list of active user keys.
func (cache *Cache) GetSummary() map[string]ActiveUser {
	summaryData := make(map[string]ActiveUser)
	for d, activeUser := range cache.UserKeys {
		summaryInfo := d.Name
		if d.Slot != "" {
			summaryInfo = fmt.Sprintf("%s-%s", d.Name, d.Slot)
		}
		summaryData[summaryInfo] = activeUser
	}
	return summaryData
}

// Flush removes all delegated keys. It returns true if the cache
// wasn't empty (i.e. there were active users removed), and false if
// the cache was empty.
func (cache *Cache) Flush() bool {
	if len(cache.UserKeys) == 0 {
		return false
	}

	cache.lock.Lock()
	for d := range cache.UserKeys {
		delete(cache.UserKeys, d)
	}
	cache.lock.Unlock()

	return true
}

// Refresh purges all expired keys. It returns the number of
// delegations that were removed.
func (cache *Cache) Refresh() int {
	var removed int

	for d, active := range cache.UserKeys {
		if active.Usage.Expiry.Before(time.Now()) || !cache.generationValid(d.Name, active.Generation) {
			log.Println("Record expired", d.Name, d.Slot, active.Usage.Users, active.Usage.Labels, active.Usage.Expiry)
			removed++
			delete(cache.UserKeys, d)
		}
	}

	return removed
}

// AddKeyFromRecord decrypts a key for a given record and adds it to the cache.
func (cache *Cache) AddKeyFromRecord(record passvault.PasswordRecord, name, password string, users, labels []string, uses int, slot, durationString string) (err error) {
	var current ActiveUser

	cache.Refresh()

	// compute exipiration
	duration, err := time.ParseDuration(durationString)
	if err != nil {
		return
	}
	current.Usage.Uses = uses
	current.Usage.Expiry = time.Now().Add(duration)
	current.Usage.Users = users
	current.Usage.Labels = labels

	// get decryption keys
	switch record.Type {
	case passvault.RSARecord:
		current.rsaKey, err = record.GetKeyRSA(password)
		if err != nil {
			return
		}
		current.Key = x509.MarshalPKCS1PrivateKey(&current.rsaKey)
	case passvault.ECCRecord:
		current.eccKey, err = record.GetKeyECC(password)
		if err != nil {
			return
		}
		current.Key, err = x509.MarshalECPrivateKey(current.eccKey)
	default:
		err = errors.New("Unknown record type")
	}

	if err != nil {
		return
	}

	// set types
	current.Type = record.Type
	current.Admin = record.Admin
	current.Generation = record.Generation

	// add current to map (overwriting previous for this name)
	cache.setUser(current, name, slot)

	// Register the generation this delegation belongs to. Any older
	// delegation still in the cache is now stale and is pruned.
	cache.SetGeneration(name, record.Generation)

	return
}

// DecryptKey decrypts a 16 byte key using the key corresponding to the name parameter
// For RSA and EC keys, the cached RSA/EC key is used to decrypt
// the pubEncryptedKey which is then used to decrypt the input
// buffer.
func (cache *Cache) DecryptKey(in []byte, name, user string, labels []string, pubEncryptedKey []byte) (out []byte, err error) {
	cache.Refresh()

	decryptKey, slot, ok := cache.MatchUser(name, user, labels)
	if !ok {
		return nil, errors.New("Key not delegated")
	}

	var aesKey []byte

	// pick the aesKey to use for decryption
	switch decryptKey.Type {
	case passvault.RSARecord:
		// extract the aes key from the pubEncryptedKey
		aesKey, err = rsa.DecryptOAEP(sha1.New(), rand.Reader, &decryptKey.rsaKey, pubEncryptedKey, nil)
		if err != nil {
			return out, err
		}
	case passvault.ECCRecord:
		// extract the aes key from the pubEncryptedKey
		aesKey, err = ecdh.Decrypt(decryptKey.eccKey, pubEncryptedKey)

		if err != nil {
			return out, err
		}
	default:
		return nil, errors.New("unknown type")
	}

	// decrypt
	aesSession, err := aes.NewCipher(aesKey)
	if err != nil {
		return out, err
	}
	out = make([]byte, 16)
	aesSession.Decrypt(out, in)

	cache.useKey(name, user, slot, labels)

	return
}

// DecryptShares decrypts an array of 16 byte shares using the key corresponding
// to the name parameter.
func (cache *Cache) DecryptShares(in [][]byte, name, user string, labels []string, pubEncryptedKey []byte) (out [][]byte, err error) {
	cache.Refresh()

	decryptKey, slot, ok := cache.MatchUser(name, user, labels)
	if !ok {
		return nil, errors.New("Key not delegated")
	}

	var aesKey []byte

	// pick the aesKey to use for decryption
	switch decryptKey.Type {
	case passvault.RSARecord:
		// extract the aes key from the pubEncryptedKey
		aesKey, err = rsa.DecryptOAEP(sha1.New(), rand.Reader, &decryptKey.rsaKey, pubEncryptedKey, nil)
		if err != nil {
			return
		}
	case passvault.ECCRecord:
		// extract the aes key from the pubEncryptedKey
		aesKey, err = ecdh.Decrypt(decryptKey.eccKey, pubEncryptedKey)

		if err != nil {
			return
		}
	default:
		return nil, errors.New("unknown type")
	}

	// decrypt
	aesSession, err := aes.NewCipher(aesKey)
	if err != nil {
		return
	}

	for _, encShare := range in {
		tmp := make([]byte, 16)
		aesSession.Decrypt(tmp, encShare)

		out = append(out, tmp)
	}

	cache.useKey(name, user, slot, labels)

	return
}

// DelegateStatus will return a list of admins who have delegated to a particular user, for a particular label.
// This is useful information to have when determining the status of an order and conveying order progress.
func (cache *Cache) DelegateStatus(name string, labels, admins []string) (adminsDelegated []string, hasDelegated int) {
	// Iterate over the admins of the ciphertext to look for users
	// who have already delegated the label to the delegatee.
	for _, admin := range admins {
		for di, use := range cache.UserKeys {
			if di.Name != admin {
				continue
			}
			if !cache.generationValid(di.Name, use.Generation) {
				continue
			}
			nameFound := false
			for _, user := range use.Users {
				if user == name {
					nameFound = true
				}
			}
			for _, ol := range use.Labels {
				for _, il := range labels {
					if ol == il {
						if nameFound {
							adminsDelegated = append(adminsDelegated, admin)
							hasDelegated++
						}
					}
				}
			}
		}
	}
	return
}

// Restore unmarshals the private key stored in the delegator to the
// appropriate private structure.
func (cache *Cache) Restore() (err error) {
	for index, uk := range cache.UserKeys {
		if len(uk.Key) == 0 {
			return errors.New("keycache: no private key in active user")
		}

		rsaPriv, err := x509.ParsePKCS1PrivateKey(uk.Key)
		if err == nil {
			uk.rsaKey = *rsaPriv
			cache.UserKeys[index] = uk
			continue
		}

		ecPriv, err := x509.ParseECPrivateKey(uk.Key)
		if err == nil {
			uk.eccKey = ecPriv
			cache.UserKeys[index] = uk
			continue
		}

		return err
	}

	return nil
}
