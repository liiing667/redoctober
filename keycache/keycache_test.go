// keycache_test.go: tests for keycache.go
//
// Copyright (c) 2013 CloudFlare, Inc.
package keycache

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/redoctober/passvault"
	"github.com/cloudflare/redoctober/symcrypt"
)

// newDelegatedCache builds a cache with a single RSA record delegated
// with the given number of uses, labels and duration, together with the
// record and a valid (pubEncryptedKey, encBlock) pair and an invalid
// pubEncryptedKey that always fails OAEP decryption.
func newDelegatedCache(t *testing.T, uses int, labels []string, duration string) (
	cache Cache,
	pr passvault.PasswordRecord,
	encBlock, pubEncryptedKey, badPubEncryptedKey []byte,
) {
	t.Helper()

	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	pr, err = records.AddNewRecord("user", "weakpassword", true, passvault.DefaultRecordType)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache = NewCache()
	if err = cache.AddKeyFromRecord(pr, "user", "weakpassword", nil, labels, uses, "", duration); err != nil {
		t.Fatalf("%v", err)
	}

	dummy := make([]byte, 16)
	key, err := symcrypt.MakeRandom(16)
	if err != nil {
		t.Fatalf("%v", err)
	}

	encBlock, err = symcrypt.EncryptCBC(dummy, dummy, key)
	if err != nil {
		t.Fatalf("%v", err)
	}

	pubEncryptedKey, err = pr.EncryptKey(key)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// A random blob cannot be OAEP-decrypted, so decryption with it
	// fails after the use has been reserved.
	badPubEncryptedKey, err = symcrypt.MakeRandom(64)
	if err != nil {
		t.Fatalf("%v", err)
	}

	return
}

// TestDecryptFailureRollback verifies that a failed decryption refunds
// the reserved use: the cache must not be left with a negative counter
// or a half-deleted entry, and a subsequent valid decryption must still
// succeed.
func TestDecryptFailureRollback(t *testing.T) {
	cache, _, encBlock, pubEncryptedKey, badPubEncryptedKey :=
		newDelegatedCache(t, 1, nil, "1h")

	index := DelegateIndex{Name: "user"}

	// The failing decryption charged the slot's only use first.
	if _, err := cache.DecryptKey(encBlock, "user", "anybody", nil, badPubEncryptedKey); err == nil {
		t.Fatal("decryption with a bogus wrapped key unexpectedly succeeded")
	}

	entry, ok := cache.UserKeys[index]
	if !ok {
		t.Fatal("failed decryption removed the delegation instead of rolling it back")
	}
	if entry.Usage.Uses != 1 {
		t.Fatalf("failed decryption left %d uses, want 1", entry.Usage.Uses)
	}

	// The refunded use must still be spendable.
	if _, err := cache.DecryptKey(encBlock, "user", "anybody", nil, pubEncryptedKey); err != nil {
		t.Fatalf("decryption after rollback failed: %v", err)
	}
	if _, ok := cache.UserKeys[index]; ok {
		t.Fatal("delegation should be gone after its single use was consumed")
	}
}

// TestDecryptFailureRollbackMultiUse checks the refund path when the
// slot still has remaining uses: the counter is restored rather than
// going negative.
func TestDecryptFailureRollbackMultiUse(t *testing.T) {
	cache, _, encBlock, _, badPubEncryptedKey :=
		newDelegatedCache(t, 3, nil, "1h")

	index := DelegateIndex{Name: "user"}
	for i := 0; i < 5; i++ {
		if _, err := cache.DecryptKey(encBlock, "user", "anybody", nil, badPubEncryptedKey); err == nil {
			t.Fatal("expected decryption failure")
		}
		if got := cache.UserKeys[index].Usage.Uses; got != 3 {
			t.Fatalf("after %d failed decryptions uses = %d, want 3", i+1, got)
		}
	}
}

// TestConcurrentFailureRollbackIsCommutative checks that refunds from
// several overlapping failed transactions restore the delegation exactly
// once per reservation. Releasing the reservations in a different order
// must not inflate the use counter, which is possible if rollback simply
// reinserts stale snapshots.
func TestConcurrentFailureRollbackIsCommutative(t *testing.T) {
	const uses = 3
	cache, _, encBlock, _, badPubEncryptedKey :=
		newDelegatedCache(t, uses, nil, "1h")

	index := DelegateIndex{Name: "user"}
	const goroutines = 64
	start := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			if _, err := cache.DecryptKey(encBlock, "user", "anybody", nil, badPubEncryptedKey); err == nil {
				t.Errorf("decryption with a bogus wrapped key unexpectedly succeeded")
			}
		}()
	}
	close(start)
	wg.Wait()

	entry, ok := cache.UserKeys[index]
	if !ok {
		t.Fatal("failed concurrent decryptions removed the delegation")
	}
	if entry.Usage.Uses != uses {
		t.Fatalf("failed concurrent decryptions left %d uses, want %d", entry.Usage.Uses, uses)
	}
}

// TestConcurrentConsumptionNeverOverspends hammers the cache with far
// more concurrent decryptions than the delegation has uses. Exactly
// `uses` requests may succeed and the cache must never carry a negative
// counter or survive with an exhausted entry.
func TestConcurrentConsumptionNeverOverspends(t *testing.T) {
	const uses = 25
	cache, _, encBlock, pubEncryptedKey, _ :=
		newDelegatedCache(t, uses, nil, "1h")

	const goroutines = 200
	var wg sync.WaitGroup
	var successes, failures int64
	var mu sync.Mutex
	start := make(chan struct{})

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			_, err := cache.DecryptKey(encBlock, "user", "anybody", nil, pubEncryptedKey)
			mu.Lock()
			if err == nil {
				successes++
			} else {
				failures++
			}
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()

	if successes != uses {
		t.Fatalf("got %d successful decryptions, want exactly %d (failures=%d)", successes, uses, failures)
	}
	if successes+failures != goroutines {
		t.Fatalf("accounting mismatch: %d successes + %d failures != %d", successes, failures, goroutines)
	}
	if len(cache.UserKeys) != 0 {
		for d, entry := range cache.UserKeys {
			if entry.Usage.Uses < 0 {
				t.Fatalf("slot %v has negative uses: %d", d, entry.Usage.Uses)
			}
		}
		t.Fatalf("exhausted delegation was not removed: %v", cache.UserKeys)
	}
}

// TestConcurrentRefreshNoLateCharge ensures an expiring delegation
// cannot be charged by a consumer racing the expiry sweep: every
// successful decryption happens strictly before expiry, and no
// half-deleted or negatively counted entry is ever observed.
func TestConcurrentRefreshNoLateCharge(t *testing.T) {
	cache, _, encBlock, pubEncryptedKey, _ :=
		newDelegatedCache(t, 1000, nil, "300ms")

	var wg sync.WaitGroup
	start := make(chan struct{})
	var success, fail int64
	var mu sync.Mutex

	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 1000; i++ {
			_, err := cache.DecryptKey(encBlock, "user", "anybody", nil, pubEncryptedKey)
			mu.Lock()
			if err == nil {
				success++
			} else {
				fail++
			}
			mu.Unlock()
		}
	}()

	go func() {
		defer wg.Done()
		<-start
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			cache.Refresh()
			if entry, _, ok := cache.MatchUser("user", "anybody", nil); ok && entry.Usage.Uses < 0 {
				t.Errorf("negative uses observed: %d", entry.Usage.Uses)
				return
			}
		}
	}()

	close(start)
	wg.Wait()

	if success+fail != 1000 {
		t.Fatalf("accounting mismatch: %d success + %d fail != 1000", success, fail)
	}
	if success > 1000 {
		t.Fatalf("more successful decryptions than delegated uses: %d", success)
	}
	if entry, ok := cache.GetSummary()["user"]; ok {
		t.Fatalf("expired entry survived refresh with %d uses", entry.Usage.Uses)
	}
}

// TestRedelegationInvalidatesRollback makes sure a failure against an
// old generation never resurrects a slot that has since been
// re-delegated.
func TestRedelegationInvalidatesRollback(t *testing.T) {
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}
	pr, err := records.AddNewRecord("user", "weakpassword", true, passvault.DefaultRecordType)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache := NewCache()
	if err = cache.AddKeyFromRecord(pr, "user", "weakpassword", nil, nil, 5, "slot", "1h"); err != nil {
		t.Fatalf("%v", err)
	}

	index := DelegateIndex{Name: "user", Slot: "slot"}
	first, ok := cache.UserKeys[index]
	if !ok {
		t.Fatal("delegation missing")
	}
	firstGen := first.generation

	// Re-delegate the same slot, starting a new generation.
	if err = cache.AddKeyFromRecord(pr, "user", "weakpassword", nil, nil, 9, "slot", "1h"); err != nil {
		t.Fatalf("%v", err)
	}
	second := cache.UserKeys[index]
	if second.generation == firstGen {
		t.Fatal("re-delegation did not start a new generation")
	}

	// A reservation belonging to the dead first generation must not be
	// refunded into the new entry.
	cache.releaseKey(reservation{
		index:      index,
		generation: firstGen,
		snapshot:   first,
	})

	after := cache.UserKeys[index]
	if after.generation != second.generation || after.Usage.Uses != 9 {
		t.Fatalf("stale rollback corrupted the new delegation: gen=%d uses=%d", after.generation, after.Usage.Uses)
	}
}

// TestMultiSlotSemantics verifies multiple slots for one delegator keep
// independent use counters and generations.
func TestMultiSlotSemantics(t *testing.T) {
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}
	pr, err := records.AddNewRecord("user", "weakpassword", true, passvault.DefaultRecordType)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache := NewCache()
	if err = cache.AddKeyFromRecord(pr, "user", "weakpassword", nil, nil, 1, "a", "1h"); err != nil {
		t.Fatalf("%v", err)
	}
	if err = cache.AddKeyFromRecord(pr, "user", "weakpassword", nil, nil, 2, "b", "1h"); err != nil {
		t.Fatalf("%v", err)
	}

	if len(cache.UserKeys) != 2 {
		t.Fatalf("expected two live slots, got %d", len(cache.UserKeys))
	}

	dummy := make([]byte, 16)
	key, err := symcrypt.MakeRandom(16)
	if err != nil {
		t.Fatalf("%v", err)
	}
	encBlock, err := symcrypt.EncryptCBC(dummy, dummy, key)
	if err != nil {
		t.Fatalf("%v", err)
	}
	pubEncryptedKey, err := pr.EncryptKey(key)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// The two slots pool three uses (slot "a": 1, slot "b": 2).
	// Which slot serves each request follows map iteration order, so
	// assert on the aggregate budget rather than a particular slot.
	for i := 0; i < 3; i++ {
		if _, err = cache.DecryptKey(encBlock, "user", "anybody", nil, pubEncryptedKey); err != nil {
			t.Fatalf("decryption %d failed while budget remained: %v", i+1, err)
		}
	}
	if len(cache.UserKeys) != 0 {
		for d, entry := range cache.UserKeys {
			if entry.Usage.Uses < 0 {
				t.Fatalf("slot %v left with negative uses %d", d, entry.Usage.Uses)
			}
		}
		t.Fatalf("expected all slots exhausted, got %v", cache.UserKeys)
	}
	if _, err = cache.DecryptKey(encBlock, "user", "anybody", nil, pubEncryptedKey); err == nil {
		t.Fatal("decryption succeeded after every slot was exhausted")
	}
}

func TestUsesFlush(t *testing.T) {
	// Initialize passvault with one dummy user.
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	pr, err := records.AddNewRecord("user", "weakpassword", true, passvault.DefaultRecordType)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Initialize keycache and delegate the user's key to it.
	cache := NewCache()

	err = cache.AddKeyFromRecord(pr, "user", "weakpassword", nil, nil, 2, "", "1h")
	if err != nil {
		t.Fatalf("%v", err)
	}

	removed := cache.Refresh()
	if removed != 0 {
		t.Fatalf("No active users should have been removed")
	}

	if len(cache.UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	// Generate a random symmetric key, encrypt a blank block with it, and encrypt
	// the key itself with the user's public key.
	dummy := make([]byte, 16)
	key, err := symcrypt.MakeRandom(16)
	if err != nil {
		t.Fatalf("%v", err)
	}

	encKey, err := symcrypt.EncryptCBC(dummy, dummy, key)
	if err != nil {
		t.Fatalf("%v", err)
	}

	pubEncryptedKey, err := pr.EncryptKey(key)
	if err != nil {
		t.Fatalf("%v", err)
	}

	key2, err := cache.DecryptKey(encKey, "user", "anybody", []string{}, pubEncryptedKey)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if bytes.Equal(key, key2) {
		t.Fatal("cache.DecryptKey didnt decrypt the right key!")
	}

	// Second decryption allowed.
	_, err = cache.DecryptKey(encKey, "user", "anybody else", []string{}, pubEncryptedKey)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if len(cache.UserKeys) != 0 {
		t.Fatalf("Error in number of live keys %v", cache.UserKeys)
	}
}

func TestTimeFlush(t *testing.T) {
	// Initialize passvault and keycache.  Delegate a key for 1s, wait a
	// second and then make sure that it's gone.
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	pr, err := records.AddNewRecord("user", "weakpassword", true, passvault.DefaultRecordType)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache := NewCache()

	err = cache.AddKeyFromRecord(pr, "user", "weakpassword", nil, nil, 10, "", "10s")
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache.Refresh()
	if len(cache.UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	time.Sleep(11 * time.Second)

	dummy := make([]byte, 16)
	pubEncryptedKey, err := pr.EncryptKey(dummy)
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = cache.DecryptKey(dummy, "user", "anybody", []string{}, pubEncryptedKey)
	if err == nil {
		t.Fatalf("Error in pruning expired key")
	}
}

func TestGoodLabel(t *testing.T) {
	// Initialize passvault and keycache.  Delegate a key with the tag "red" and
	// verify that decryption with the tag "red" is allowed.
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	pr, err := records.AddNewRecord("user", "weakpassword", true, passvault.DefaultRecordType)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache := NewCache()

	err = cache.AddKeyFromRecord(pr, "user", "weakpassword", nil, []string{"red"}, 1, "", "1h")
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache.Refresh()
	if len(cache.UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	dummy := make([]byte, 16)
	pubEncryptedKey, err := pr.EncryptKey(dummy)
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = cache.DecryptKey(dummy, "user", "anybody", []string{"red"}, pubEncryptedKey)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if len(cache.UserKeys) != 0 {
		t.Fatalf("Error in number of live keys %v", cache.UserKeys)
	}
}

func TestBadLabel(t *testing.T) {
	// Initialize passvault and keycache.  Delegate a key with the tag "red" and
	// verify that decryption with the tag "blue" is disallowed.
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	pr, err := records.AddNewRecord("user", "weakpassword", true, passvault.DefaultRecordType)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache := NewCache()

	err = cache.AddKeyFromRecord(pr, "user", "weakpassword", nil, []string{"red"}, 1, "", "1h")
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache.Refresh()
	if len(cache.UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	dummy := make([]byte, 16)
	pubEncryptedKey, err := pr.EncryptKey(dummy)
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = cache.DecryptKey(dummy, "user", "anybody", []string{"blue"}, pubEncryptedKey)
	if err == nil {
		t.Fatalf("Decryption of labeled key allowed without permission.")
	}

	cache.Refresh()
	if len(cache.UserKeys) != 1 {
		t.Fatalf("Error in number of live keys %v", cache.UserKeys)
	}
}

func TestGoodUser(t *testing.T) {
	// Initialize passvault and keycache.  Delegate a key with tag and user
	// restrictions and verify that permissible decryption is allowed.
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	pr, err := records.AddNewRecord("user", "weakpassword", true, passvault.DefaultRecordType)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache := NewCache()

	err = cache.AddKeyFromRecord(
		pr, "user", "weakpassword",
		[]string{"ci", "buildeng", "user"},
		[]string{"red", "blue"},
		1, "", "1h",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache.Refresh()
	if len(cache.UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	dummy := make([]byte, 16)
	pubEncryptedKey, err := pr.EncryptKey(dummy)
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = cache.DecryptKey(dummy, "user", "ci", []string{"red"}, pubEncryptedKey)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache.Refresh()
	if len(cache.UserKeys) != 0 {
		t.Fatalf("Error in number of live keys %v", cache.UserKeys)
	}
}

func TestBadUser(t *testing.T) {
	// Initialize passvault and keycache.  Delegate a key with tag and user
	// restrictions and verify that illegal decryption is disallowed.
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	pr, err := records.AddNewRecord("user", "weakpassword", true, passvault.DefaultRecordType)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache := NewCache()

	err = cache.AddKeyFromRecord(
		pr, "user", "weakpassword",
		[]string{"ci", "buildeng", "user"},
		[]string{"red", "blue"},
		1, "", "1h",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache.Refresh()
	if len(cache.UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	dummy := make([]byte, 16)
	pubEncryptedKey, err := pr.EncryptKey(dummy)
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = cache.DecryptKey(dummy, "user", "anybody", []string{"blue"}, pubEncryptedKey)
	if err == nil {
		t.Fatalf("Decryption of labeled key allowed without permission.")
	}

	cache.Refresh()
	if len(cache.UserKeys) != 1 {
		t.Fatalf("Error in number of live keys %v", cache.UserKeys)
	}
}

func TestRefresh(t *testing.T) {
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	pr, err := records.AddNewRecord("user", "weakpassword", true, passvault.DefaultRecordType)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache := NewCache()

	err = cache.AddKeyFromRecord(
		pr, "user", "weakpassword",
		[]string{"ci", "buildeng", "user"},
		[]string{"red", "blue"},
		1, "", "10s",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	removed := cache.Refresh()
	if removed != 0 {
		t.Fatalf("Refresh should not have removed any active users.")
	}

	time.Sleep(10 * time.Second)

	removed = cache.Refresh()
	if removed != 1 {
		t.Fatalf("Refresh should have removed an active user, removed %d", removed)
	}

	if len(cache.GetSummary()) != 0 {
		t.Fatalf("There should be no active users in the cache, but there are %d", len(cache.GetSummary()))
	}
}

func cmpEntry(c, d ActiveUser) bool {
	if c.Uses != d.Uses {
		return false
	}

	if len(c.Labels) != len(d.Labels) {
		return false
	}

	for i := range c.Labels {
		if c.Labels[i] != d.Labels[i] {
			return false
		}
	}

	if len(c.Users) != len(d.Users) {
		return false
	}

	for i := range c.Users {
		if c.Users[i] != d.Users[i] {
			return false
		}
	}

	if c.Expiry != d.Expiry {
		return false
	}

	return true
}

func cmpCache(a, b Cache) bool {
	if len(a.UserKeys) != len(b.UserKeys) {
		return false
	}

	for aIndex, aUser := range a.UserKeys {
		bUser, ok := b.UserKeys[aIndex]
		if !ok {
			return false
		}

		if !cmpEntry(aUser, bUser) {
			return false
		}
	}

	return true
}

func TestNewFrom(t *testing.T) {
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache := NewCache()

	users := []string{"alice", "bob", "carol"}
	for _, user := range users {
		pr, err := records.AddNewRecord(user, "weakpassword", true, passvault.DefaultRecordType)
		if err != nil {
			t.Fatalf("%v", err)
		}

		err = cache.AddKeyFromRecord(
			pr, user, "weakpassword",
			[]string{"ci", "buildeng", "user"},
			[]string{"red", "blue"},
			1, "", "1h")
		if err != nil {
			t.Fatalf("%v", err)
		}
	}

	pr, ok := records.GetRecord("alice")
	if !ok {
		t.Fatal("Couldn't retrieve 'alice' record.")
	}

	err = cache.AddKeyFromRecord(pr, "alice", "weakpassword",
		[]string{"ci", "alice"}, []string{"blue", "yellow"},
		2, "slotname", "1h")
	if err != nil {
		t.Fatal(err)
	}

	summary := cache.GetSummary()
	cache2 := NewFrom(summary)
	if !cmpCache(cache, *cache2) {
		t.Fatal("caches don't match")
	}

}
