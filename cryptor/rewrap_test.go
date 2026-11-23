// rewrap_test.go: tests for atomic re-encryption.
//
// Copyright (c) 2013 CloudFlare, Inc.

package cryptor

import (
	"fmt"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/cloudflare/redoctober/config"
	"github.com/cloudflare/redoctober/keycache"
	"github.com/cloudflare/redoctober/passvault"
	"github.com/cloudflare/redoctober/persist"
)

// newTestCryptor builds a cryptor backed by a memory vault containing the
// named users, each of which has delegated `uses` key uses.
func newTestCryptor(t *testing.T, names []string, uses int) (*Cryptor, map[string]passvault.PasswordRecord) {
	cache := keycache.NewCache()
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	cfg := &config.Delegations{Persist: false}
	store, err := persist.New(cfg)
	if err != nil {
		t.Fatal(err.Error())
	}

	c := &Cryptor{records: &records, cache: &cache, persist: store}
	recs := make(map[string]passvault.PasswordRecord, len(names))
	for _, name := range names {
		pr, err := records.AddNewRecord(name, "weakpassword", true, passvault.DefaultRecordType)
		if err != nil {
			t.Fatalf("%v", err)
		}
		recs[name] = pr
		if err = cache.AddKeyFromRecord(pr, name, "weakpassword", nil, nil, uses, "", "1h"); err != nil {
			t.Fatalf("%v", err)
		}
	}
	return c, recs
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// TestReEncryptPreservesOwners is the acceptance check: the output of a
// key-rotation re-encryption must expose exactly the same owners as the
// source ciphertext.
func TestReEncryptPreservesOwners(t *testing.T) {
	names := []string{"Alice", "Bob", "Carol"}
	c, _ := newTestCryptor(t, names, 100)

	source, err := c.Encrypt(
		[]byte("rotation payload"),
		[]string{"blue"},
		nil,
		AccessStructure{Minimum: 2, Names: names},
	)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	sourceOwners, sourceLabels, sourcePredicate, err := c.GetOwners(source)
	if err != nil {
		t.Fatalf("source owners: %v", err)
	}

	// A rotation request carries no access structure at all.
	out, err := c.ReEncrypt(source, "Alice", nil, nil, nil)
	if err != nil {
		t.Fatalf("re-encrypt: %v", err)
	}

	outOwners, outLabels, outPredicate, err := c.GetOwners(out)
	if err != nil {
		t.Fatalf("output owners: %v", err)
	}

	if !reflect.DeepEqual(sortedStrings(sourceOwners), sortedStrings(outOwners)) {
		t.Fatalf("owners changed during rewrap: source=%v output=%v", sourceOwners, outOwners)
	}
	if !reflect.DeepEqual(sortedStrings(sourceLabels), sortedStrings(outLabels)) {
		t.Fatalf("labels changed during rewrap: source=%v output=%v", sourceLabels, outLabels)
	}
	if sourcePredicate != outPredicate {
		t.Fatalf("predicate changed during rewrap: source=%q output=%q", sourcePredicate, outPredicate)
	}

	// The rotated ciphertext must still decrypt to the original plaintext
	// under the same delegations.
	plain, _, _, _, secure, err := c.Decrypt(out, "Alice")
	if err != nil {
		t.Fatalf("decrypt rewrapped: %v", err)
	}
	if !secure {
		t.Fatalf("rewrapped ciphertext is not locked")
	}
	if string(plain) != "rotation payload" {
		t.Fatalf("plaintext changed: %q", plain)
	}
}

// TestReEncryptPreservesLeftRightOwners covers the legacy left/right owner
// access structure.
func TestReEncryptPreservesLeftRightOwners(t *testing.T) {
	c, _ := newTestCryptor(t, []string{"Alice", "Bob", "Carl"}, 100)

	source, err := c.Encrypt(
		[]byte("left right payload"),
		nil,
		nil,
		AccessStructure{LeftNames: []string{"Alice", "Bob"}, RightNames: []string{"Bob", "Carl"}},
	)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	out, err := c.ReEncrypt(source, "Alice", nil, nil, nil)
	if err != nil {
		t.Fatalf("re-encrypt: %v", err)
	}

	sourceOwners, _, _, err := c.GetOwners(source)
	if err != nil {
		t.Fatalf("source owners: %v", err)
	}
	outOwners, _, _, err := c.GetOwners(out)
	if err != nil {
		t.Fatalf("output owners: %v", err)
	}
	if !reflect.DeepEqual(sortedStrings(sourceOwners), sortedStrings(outOwners)) {
		t.Fatalf("left/right owners changed: source=%v output=%v", sourceOwners, outOwners)
	}

	if _, _, _, _, _, err = c.Decrypt(out, "Alice"); err != nil {
		t.Fatalf("decrypt rewrapped left/right ciphertext: %v", err)
	}
}

// TestReEncryptPreservesPredicate verifies that predicate-based ciphertexts
// keep their predicate and shares after a rotation.
func TestReEncryptPreservesPredicate(t *testing.T) {
	c, _ := newTestCryptor(t, []string{"Alice", "Bob", "Carl"}, 100)

	predicate := "(2, (1, Alice, Bob), Carl)"
	source, err := c.Encrypt(
		[]byte("predicate payload"),
		[]string{"blue"},
		nil,
		AccessStructure{Predicate: predicate},
	)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	out, err := c.ReEncrypt(source, "Alice", nil, nil, nil)
	if err != nil {
		t.Fatalf("re-encrypt: %v", err)
	}

	sourceOwners, sourceLabels, sourcePredicate, err := c.GetOwners(source)
	if err != nil {
		t.Fatalf("source owners: %v", err)
	}
	outOwners, outLabels, outPredicate, err := c.GetOwners(out)
	if err != nil {
		t.Fatalf("output owners: %v", err)
	}
	if sourcePredicate != outPredicate || outPredicate != predicate {
		t.Fatalf("predicate not preserved: source=%q output=%q", sourcePredicate, outPredicate)
	}
	if !reflect.DeepEqual(sortedStrings(sourceOwners), sortedStrings(outOwners)) {
		t.Fatalf("predicate owners changed: source=%v output=%v", sourceOwners, outOwners)
	}
	if !reflect.DeepEqual(sortedStrings(sourceLabels), sortedStrings(outLabels)) {
		t.Fatalf("predicate labels changed: source=%v output=%v", sourceLabels, outLabels)
	}

	if _, _, _, _, _, err = c.Decrypt(out, "Alice"); err != nil {
		t.Fatalf("decrypt rewrapped predicate ciphertext: %v", err)
	}
}

// TestReEncryptNoLabels ensures ciphertexts created without labels still
// re-encrypt successfully and remain label-free.
func TestReEncryptNoLabels(t *testing.T) {
	c, _ := newTestCryptor(t, []string{"Alice", "Bob", "Carol"}, 100)

	source, err := c.Encrypt(
		[]byte("unlabelled payload"),
		nil,
		nil,
		AccessStructure{Minimum: 2, Names: []string{"Alice", "Bob", "Carol"}},
	)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	out, err := c.ReEncrypt(source, "Alice", nil, nil, nil)
	if err != nil {
		t.Fatalf("re-encrypt: %v", err)
	}

	_, labels, _, err := c.GetOwners(out)
	if err != nil {
		t.Fatalf("owners: %v", err)
	}
	if len(labels) != 0 {
		t.Fatalf("unlabelled ciphertext gained labels: %v", labels)
	}
}

// TestReEncryptExplicitOverride checks that a caller-supplied destination
// access structure and label set are applied instead of the source ones.
func TestReEncryptExplicitOverride(t *testing.T) {
	c, _ := newTestCryptor(t, []string{"Alice", "Bob", "Carol"}, 100)

	source, err := c.Encrypt(
		[]byte("override payload"),
		[]string{"blue"},
		nil,
		AccessStructure{Minimum: 2, Names: []string{"Alice", "Bob", "Carol"}},
	)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	out, err := c.ReEncrypt(
		source,
		"Alice",
		&AccessStructure{Minimum: 1, Names: []string{"Alice"}},
		[]string{"red"},
		nil,
	)
	if err != nil {
		t.Fatalf("re-encrypt: %v", err)
	}

	outOwners, outLabels, _, err := c.GetOwners(out)
	if err != nil {
		t.Fatalf("owners: %v", err)
	}
	if !reflect.DeepEqual(sortedStrings(outOwners), []string{"Alice"}) {
		t.Fatalf("override owners not applied: %v", outOwners)
	}
	if !reflect.DeepEqual(sortedStrings(outLabels), []string{"red"}) {
		t.Fatalf("override labels not applied: %v", outLabels)
	}
}

// TestReEncryptRollsBackDelegationOnFailure makes sure that a failed
// rewrap does not consume a delegated key use: the cache is restored and
// no partial output is ever returned.
func TestReEncryptRollsBackDelegationOnFailure(t *testing.T) {
	c, _ := newTestCryptor(t, []string{"Alice", "Bob", "Carol"}, 100)

	source, err := c.Encrypt(
		[]byte("rollback payload"),
		nil,
		nil,
		AccessStructure{Minimum: 2, Names: []string{"Alice", "Bob", "Carol"}},
	)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	before := c.cache.Snapshot()

	// Dave does not exist, so wrapping the destination must fail after the
	// source key was unwrapped.
	_, err = c.ReEncrypt(
		source,
		"Alice",
		&AccessStructure{Minimum: 1, Names: []string{"Dave"}},
		nil,
		nil,
	)
	if err == nil {
		t.Fatalf("expected re-encrypt to fail for an unknown owner")
	}

	after := c.cache.Snapshot()
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("delegated key cache changed after a failed re-encrypt")
	}

	// The source ciphertext must still be usable (its delegations were not
	// burned by the failed attempt).
	if _, err := c.ReEncrypt(source, "Alice", nil, nil, nil); err != nil {
		t.Fatalf("retry after failure did not succeed: %v", err)
	}
}

// TestReEncryptConcurrentRewraps serialises concurrent rotations: every
// goroutine must get a complete, valid ciphertext.
func TestReEncryptConcurrentRewraps(t *testing.T) {
	c, _ := newTestCryptor(t, []string{"Alice", "Bob", "Carol"}, 1000)

	source, err := c.Encrypt(
		[]byte("concurrent payload"),
		nil,
		nil,
		AccessStructure{Minimum: 2, Names: []string{"Alice", "Bob", "Carol"}},
	)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	sourceOwners, _, _, err := c.GetOwners(source)
	if err != nil {
		t.Fatalf("owners: %v", err)
	}

	const workers = 16
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := c.ReEncrypt(source, "Alice", nil, nil, nil)
			if err != nil {
				errs <- err
				return
			}
			outOwners, _, _, err := c.GetOwners(out)
			if err != nil {
				errs <- err
				return
			}
			if !reflect.DeepEqual(sortedStrings(sourceOwners), sortedStrings(outOwners)) {
				errs <- fmt.Errorf("owners mismatch: source=%v output=%v", sourceOwners, outOwners)
				return
			}
			if _, _, _, _, _, err = c.Decrypt(out, "Alice"); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent rewrap failure: %v", err)
	}
}
