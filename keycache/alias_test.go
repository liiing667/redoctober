// alias_test.go: the delegation cache must be indexed by canonical
// names so that a single account never gets parallel cache entries.
//
// Copyright (c) 2013 CloudFlare, Inc.

package keycache

import (
	"testing"

	"github.com/cloudflare/redoctober/passvault"
)

func TestDelegationCacheIsCanonical(t *testing.T) {
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	pr, err := records.AddNewRecord("Alice", "weakpassword", true, passvault.RSARecord)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache := NewCache()

	// The core layer always hands the canonical name to the cache,
	// even when the request authenticated with an alias.
	if err = cache.AddKeyFromRecord(pr, "Alice", "weakpassword",
		[]string{"Bob"}, nil, 5, "", "1h"); err != nil {
		t.Fatalf("%v", err)
	}

	if len(cache.UserKeys) != 1 {
		t.Fatalf("expected one cache entry, got %d", len(cache.UserKeys))
	}

	// A second delegation for the same identity overwrites rather
	// than creating a second entry.
	if err = cache.AddKeyFromRecord(pr, "Alice", "weakpassword",
		[]string{"Bob"}, nil, 3, "slot", "1h"); err != nil {
		t.Fatalf("%v", err)
	}

	canonicalEntries := 0
	for index := range cache.UserKeys {
		if index.Name != "Alice" {
			t.Fatalf("cache entry keyed by non-canonical name %q", index.Name)
		}
		canonicalEntries++
	}
	if canonicalEntries != 2 {
		// One default slot and one named slot, both for Alice.
		t.Fatalf("expected 2 slots for the canonical identity, got %d", canonicalEntries)
	}

	if !cache.Valid("Alice", "Bob", nil) {
		t.Fatalf("delegation not valid for canonical name")
	}

	// The summary used by reports and persistence is canonical too.
	summary := cache.GetSummary()
	for name := range summary {
		if name != "Alice" && name != "Alice-slot" {
			t.Fatalf("non-canonical name %q leaked into cache summary", name)
		}
	}
}
