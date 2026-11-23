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

	rsaKey rsa.PrivateKey
	eccKey *ecdsa.PrivateKey

	// generation identifies the delegation generation that owns this
	// slot. It is bumped every time a delegation is accepted for the
	// same (Name, Slot) index and lets in-flight consumption
	// transactions detect that the slot was refreshed, re-delegated or
	// purged while they were doing cryptographic work, so their failure
	// recovery never resurrects a stale or half-deleted entry. The field
	// is unexported, so it is never serialised into summaries or the
	// persistence store.
	generation uint64
}

// Cache represents the current list of delegated keys in memory
type Cache struct {
	lock     *sync.Mutex
	UserKeys map[DelegateIndex]ActiveUser
	// nextGeneration is a monotonically increasing counter handed out
	// to every accepted delegation, giving each slot its own generation.
	nextGeneration uint64
	// slotGenerations records the latest generation ever assigned to a
	// slot, including slots whose entry has since been consumed,
	// expired or purged. It lets failure recovery tell a dead
	// reservation from a slot that was re-delegated after it died, so a
	// failed transaction never resurrects an outdated delegation.
	slotGenerations map[DelegateIndex]uint64
	// reservations counts the in-flight consumption transactions for a
	// particular slot generation. A successful transaction lowers the
	// count when it commits; a failed one lowers it when it refunds a
	// use. Keeping the count per generation makes refunds commutative:
	// releasing several reservations against the same slot restores
	// exactly the uses that were taken, even when the slot was removed
	// from UserKeys by the last reservation.
	reservations map[reservationKey]int
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
		UserKeys:        make(map[DelegateIndex]ActiveUser),
		slotGenerations: make(map[DelegateIndex]uint64),
		reservations:    make(map[reservationKey]int),
		lock:            new(sync.Mutex),
	}
}

// NewFrom takes the output of GetSummary and returns a new keycache.
func NewFrom(summary map[string]ActiveUser) *Cache {
	cache := &Cache{
		UserKeys:        make(map[DelegateIndex]ActiveUser),
		slotGenerations: make(map[DelegateIndex]uint64),
		reservations:    make(map[reservationKey]int),
		lock:            new(sync.Mutex),
	}

	for di, user := range summary {
		diSplit := strings.SplitN(di, "-", 2)
		index := DelegateIndex{
			Name: diSplit[0],
		}

		if len(diSplit) == 2 {
			index.Slot = diSplit[1]
		}
		// Restored entries start a fresh in-memory generation; they
		// never share a generation with an outstanding reservation.
		cache.nextGeneration++
		user.generation = cache.nextGeneration
		cache.slotGenerations[index] = user.generation
		cache.UserKeys[index] = user
	}

	return cache
}

// setUser takes an ActiveUser and adds it to the cache, assigning it a
// fresh slot generation. The caller must hold cache.lock.
func (cache *Cache) setUserLocked(in ActiveUser, name, slot string) {
	if cache.slotGenerations == nil {
		cache.slotGenerations = make(map[DelegateIndex]uint64)
	}
	cache.nextGeneration++
	in.generation = cache.nextGeneration
	index := DelegateIndex{Name: name, Slot: slot}
	cache.UserKeys[index] = in
	cache.slotGenerations[index] = in.generation
}

// refreshLocked purges all expired keys. It returns the number of
// delegations that were removed. The caller must hold cache.lock.
func (cache *Cache) refreshLocked(now time.Time) (removed int) {
	if cache.slotGenerations == nil {
		cache.slotGenerations = make(map[DelegateIndex]uint64)
	}

	for d, active := range cache.UserKeys {
		if active.Usage.Expiry.Before(now) {
			log.Println("Record expired", d.Name, d.Slot, active.Usage.Users, active.Usage.Labels, active.Usage.Expiry)
			removed++
			delete(cache.UserKeys, d)
			// Retire the expired generation as well. A reservation
			// that was in flight while the entry expired must never be
			// able to refund a use into a slot that cleanup has already
			// removed.
			cache.nextGeneration++
			cache.slotGenerations[d] = cache.nextGeneration
		}
	}

	return removed
}

// matchLocked returns the matching active user, its slot and a boolean
// to indicate its presence. Expired entries are treated as absent; the
// caller is responsible for having purged them with refreshLocked when
// a purge is required. The caller must hold cache.lock.
func (cache *Cache) matchLocked(name, user string, labels []string, now time.Time) (ActiveUser, string, bool) {
	var key ActiveUser
	for d, candidate := range cache.UserKeys {
		if d.Name != name {
			continue
		}
		if candidate.Usage.Expiry.Before(now) {
			continue
		}
		if candidate.Usage.matches(user, labels) {
			return candidate, d.Slot, true
		}
	}

	return key, "", false
}

// Valid returns true if matching active user is present.
func (cache *Cache) Valid(name, user string, labels []string) (present bool) {
	cache.lock.Lock()
	defer cache.lock.Unlock()

	now := time.Now()
	for d, key := range cache.UserKeys {
		if d.Name != name {
			continue
		}
		if key.Usage.Expiry.Before(now) {
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
	cache.lock.Lock()
	defer cache.lock.Unlock()

	return cache.matchLocked(name, user, labels, time.Now())
}

// reservation is the handle returned by reserveKey. It captures the
// state needed to either confirm consumption of a use or to roll it
// back if the cryptographic operation consuming the delegated key
// fails.
type reservation struct {
	index      DelegateIndex
	generation uint64
	// snapshot is the entry as it existed before the use was
	// charged. It lets releaseKey reinsert a slot whose last use had
	// removed it from the map.
	snapshot ActiveUser
}

// reservationKey identifies the in-flight reservations belonging to one
// incarnation of a slot. Re-delegating a slot starts a new incarnation,
// so reservations against the old one can never be confused with the
// new one.
type reservationKey struct {
	index      DelegateIndex
	generation uint64
}

// reserveKey is the first half of a consumption transaction. Under a
// single lock acquisition it refreshes expired delegations, looks up a
// matching slot and atomically decrements its use counter, deleting the
// slot when no uses remain. This makes expiry cleanup, MatchUser and
// the Uses decrement one indivisible operation: concurrent consumers can
// never over-spend a delegation and an expired entry can never be
// matched and charged after Refresh would have removed it.
//
// The returned ActiveUser is a copy safe to use for cryptography after
// the lock has been released; the reservation is passed to releaseKey
// once the operation completes.
func (cache *Cache) reserveKey(name, user string, labels []string) (ActiveUser, reservation, error) {
	cache.lock.Lock()
	defer cache.lock.Unlock()

	now := time.Now()
	cache.refreshLocked(now)

	held, slot, present := cache.matchLocked(name, user, labels, now)
	if !present {
		return ActiveUser{}, reservation{}, errors.New("Key not delegated")
	}

	index := DelegateIndex{Name: name, Slot: slot}
	if held.Usage.Uses <= 0 {
		// Defensive: a fully consumed slot must never carry a
		// negative counter. Drop it and report it as missing rather
		// than charging a use.
		delete(cache.UserKeys, index)
		return ActiveUser{}, reservation{}, errors.New("Key not delegated")
	}

	// Entries created directly by tests or restored from older state may
	// not have a generation yet. Give them one before handing out the
	// reservation so refunds can still be tied to this incarnation.
	if held.generation == 0 {
		if cache.slotGenerations == nil {
			cache.slotGenerations = make(map[DelegateIndex]uint64)
		}
		cache.nextGeneration++
		held.generation = cache.nextGeneration
		cache.slotGenerations[index] = held.generation
	}

	snapshot := held
	held.Usage.Uses--
	if held.Usage.Uses <= 0 {
		delete(cache.UserKeys, index)
	} else {
		cache.UserKeys[index] = held
	}

	if cache.reservations == nil {
		cache.reservations = make(map[reservationKey]int)
	}
	cache.reservations[reservationKey{index: index, generation: snapshot.generation}]++

	return snapshot, reservation{
		index:      index,
		generation: snapshot.generation,
		snapshot:   snapshot,
	}, nil
}

// commitKey is the success half of a consumption transaction. The use
// was already deducted by reserveKey; committing only releases the
// reservation bookkeeping. The slot itself is removed by reserveKey when
// its final available use is taken.
func (cache *Cache) commitKey(res reservation) {
	if res.generation == 0 {
		return
	}

	cache.lock.Lock()
	defer cache.lock.Unlock()

	key := reservationKey{index: res.index, generation: res.generation}
	if outstanding := cache.reservations[key]; outstanding > 1 {
		cache.reservations[key] = outstanding - 1
	} else {
		delete(cache.reservations, key)
	}
}

// releaseKey is the failure-recovery half of a consumption transaction.
// It restores the use reserved by reserveKey when the operation that
// consumed it fails. The slot generation captured in the reservation is
// checked first: if the slot was re-delegated, purged or expired while
// the operation was in flight, the reservation belongs to a dead
// generation and must not be resurrected. A restored entry never ends up
// with a negative use count, and a fully consumed (deleted) slot is
// reinserted rather than half-deleted.
func (cache *Cache) releaseKey(res reservation) {
	if res.generation == 0 {
		return
	}

	cache.lock.Lock()
	defer cache.lock.Unlock()

	key := reservationKey{index: res.index, generation: res.generation}
	outstanding := cache.reservations[key]
	tracked := outstanding > 0
	if tracked {
		if outstanding == 1 {
			delete(cache.reservations, key)
		} else {
			cache.reservations[key] = outstanding - 1
		}
	}

	now := time.Now()
	held, ok := cache.UserKeys[res.index]
	if !ok {
		// The slot was removed by the reservation itself (its last
		// use was charged), by Refresh or by a Flush. Restore the
		// pre-consumption snapshot only when this reservation still
		// owns the slot's latest generation (i.e. no re-delegation
		// happened) and the delegation has not expired in the
		// meantime. A newer generation having taken over means this
		// reservation is dead and must not be resurrected.
		if cache.slotGenerations[res.index] != res.generation {
			return
		}
		if res.snapshot.Usage.Expiry.Before(now) {
			return
		}
		restored := res.snapshot
		if tracked {
			// With the slot absent, every unreserved use has already
			// been charged, so this refund restores exactly one use.
			// Adding to the snapshot's old counter would double-refund
			// reservations that were released before this one.
			restored.Usage.Uses = 1
		}
		cache.UserKeys[res.index] = restored
		return
	}

	if held.generation != res.generation {
		// A fresh delegation owns this slot now; the failed
		// transaction must not touch it.
		return
	}

	if held.Usage.Expiry.Before(now) {
		return
	}

	held.Usage.Uses++
	cache.UserKeys[res.index] = held
}

// GetSummary returns the list of active user keys.
func (cache *Cache) GetSummary() map[string]ActiveUser {
	cache.lock.Lock()
	defer cache.lock.Unlock()

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
	cache.lock.Lock()
	defer cache.lock.Unlock()

	hadUsers := len(cache.UserKeys) != 0

	for d := range cache.UserKeys {
		delete(cache.UserKeys, d)
	}
	// Invalidate every generation, even when UserKeys is already empty
	// because in-flight reservations are holding the last uses. A
	// reservation that was in flight when the cache was flushed belongs
	// to a generation that can never be restored.
	for d := range cache.slotGenerations {
		delete(cache.slotGenerations, d)
	}
	for key := range cache.reservations {
		delete(cache.reservations, key)
	}

	return hadUsers
}

// Refresh purges all expired keys. It returns the number of
// delegations that were removed.
func (cache *Cache) Refresh() int {
	cache.lock.Lock()
	defer cache.lock.Unlock()

	return cache.refreshLocked(time.Now())
}

// AddKeyFromRecord decrypts a key for a given record and adds it to the cache.
func (cache *Cache) AddKeyFromRecord(record passvault.PasswordRecord, name, password string, users, labels []string, uses int, slot, durationString string) (err error) {
	var current ActiveUser

	// compute expiration; do this before touching cache state so a
	// malformed duration leaves the cache untouched.
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

	// Accept the delegation in a single transaction with the expiry
	// sweep. Overwriting a previous delegation for the same (name, slot)
	// hands out a fresh slot generation, which invalidates any
	// consumption transactions still running against the old entry.
	cache.lock.Lock()
	defer cache.lock.Unlock()

	cache.refreshLocked(time.Now())
	cache.setUserLocked(current, name, slot)

	return
}

// DecryptKey decrypts a 16 byte key using the key corresponding to the name parameter
// For RSA and EC keys, the cached RSA/EC key is used to decrypt
// the pubEncryptedKey which is then used to decrypt the input
// buffer.
func (cache *Cache) DecryptKey(in []byte, name, user string, labels []string, pubEncryptedKey []byte) (out []byte, err error) {
	// Reserve one use of the matching slot atomically. The expiry
	// sweep, the user/label match and the Uses decrement all happen
	// under one lock acquisition, so concurrent decryptions cannot
	// overspend the delegation and an expired entry cannot be charged.
	decryptKey, res, err := cache.reserveKey(name, user, labels)
	if err != nil {
		return nil, err
	}

	var aesKey []byte
	// If anything fails after the use was charged, hand it back so a
	// rejection never leaves a negative counter or a half-deleted slot.
	// The reservation generation ensures the refund only reaches the
	// delegation that actually paid.
	defer func() {
		if err != nil {
			cache.releaseKey(res)
		} else {
			cache.commitKey(res)
		}
	}()

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
		err = errors.New("unknown type")
		return nil, err
	}

	// decrypt
	aesSession, err := aes.NewCipher(aesKey)
	if err != nil {
		return out, err
	}
	out = make([]byte, 16)
	aesSession.Decrypt(out, in)

	return
}

// DecryptShares decrypts an array of 16 byte shares using the key corresponding
// to the name parameter.
func (cache *Cache) DecryptShares(in [][]byte, name, user string, labels []string, pubEncryptedKey []byte) (out [][]byte, err error) {
	// Same consumption transaction as DecryptKey: reserve the use
	// atomically and refund it if share decryption fails.
	var decryptKey ActiveUser
	var res reservation
	decryptKey, res, err = cache.reserveKey(name, user, labels)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			cache.releaseKey(res)
		} else {
			cache.commitKey(res)
		}
	}()

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
		err = errors.New("unknown type")
		return nil, err
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

	return
}

// DelegateStatus will return a list of admins who have delegated to a particular user, for a particular label.
// This is useful information to have when determining the status of an order and conveying order progress.
func (cache *Cache) DelegateStatus(name string, labels, admins []string) (adminsDelegated []string, hasDelegated int) {
	cache.lock.Lock()
	defer cache.lock.Unlock()

	// Iterate over the admins of the ciphertext to look for users
	// who have already delegated the label to the delegatee.
	for _, admin := range admins {
		for di, use := range cache.UserKeys {
			if di.Name != admin {
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
	cache.lock.Lock()
	defer cache.lock.Unlock()

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
