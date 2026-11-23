// alias_test.go: tests for canonical identity / alias handling.
//
// Copyright (c) 2013 CloudFlare, Inc.

package passvault

import (
	"io/ioutil"
	"os"
	"testing"
)

func newAliasVault(t *testing.T) Records {
	records, err := InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	if _, err = records.AddNewRecord("Alice", "password", true, RSARecord); err != nil {
		t.Fatalf("%v", err)
	}
	if _, err = records.AddNewRecord("Bob", "password", false, RSARecord); err != nil {
		t.Fatalf("%v", err)
	}

	return records
}

func TestAliasResolvesToCanonical(t *testing.T) {
	records := newAliasVault(t)

	if err := records.AddAlias("Alice", "al"); err != nil {
		t.Fatalf("AddAlias failed: %v", err)
	}

	canonical, ok := records.CanonicalName("al")
	if !ok || canonical != "Alice" {
		t.Fatalf("alias did not resolve to canonical name, got %q ok=%v", canonical, ok)
	}

	canonical, ok = records.CanonicalName("Alice")
	if !ok || canonical != "Alice" {
		t.Fatalf("canonical name changed, got %q", canonical)
	}

	pr, canonical, ok := records.GetCanonicalRecord("al")
	if !ok || canonical != "Alice" {
		t.Fatalf("GetCanonicalRecord via alias failed: %q ok=%v", canonical, ok)
	}
	if err := pr.ValidatePassword("password"); err != nil {
		t.Fatalf("record reached through alias failed password validation: %v", err)
	}

	aliases, ok := records.GetAliases("al")
	if !ok || len(aliases) != 1 || aliases[0] != "al" {
		t.Fatalf("GetAliases returned %v ok=%v", aliases, ok)
	}
}

func TestAliasConflictRejectedBeforeCommit(t *testing.T) {
	records := newAliasVault(t)

	if err := records.AddAlias("Alice", "shared"); err != nil {
		t.Fatalf("first AddAlias failed: %v", err)
	}

	// The same alias must never be claimed by a second account.
	if err := records.AddAlias("Bob", "shared"); err == nil {
		t.Fatalf("conflicting alias was accepted")
	}

	// Bob's record must be untouched by the failed commit.
	aliases, ok := records.GetAliases("Bob")
	if !ok || len(aliases) != 0 {
		t.Fatalf("failed alias commit mutated Bob's record: %v", aliases)
	}

	// The existing owner keeps the alias.
	canonical, ok := records.CanonicalName("shared")
	if !ok || canonical != "Alice" {
		t.Fatalf("alias ownership changed after conflict, got %q", canonical)
	}

	// An alias cannot shadow a canonical account name.
	if err := records.AddAlias("Bob", "Alice"); err == nil {
		t.Fatalf("alias shadowing a canonical name was accepted")
	}

	// Re-adding the same alias to the same account is rejected.
	if err := records.AddAlias("Alice", "shared"); err == nil {
		t.Fatalf("duplicate alias on same account was accepted")
	}
}

func TestAliasPasswordChangeStaysCanonical(t *testing.T) {
	records := newAliasVault(t)

	if err := records.AddAlias("Alice", "al"); err != nil {
		t.Fatalf("AddAlias failed: %v", err)
	}

	// Changing the password through the alias must update the
	// canonical record, not create a parallel one.
	if err := records.ChangePassword("al", "password", "newpassword", ""); err != nil {
		t.Fatalf("ChangePassword via alias failed: %v", err)
	}

	if records.NumRecords() != 2 {
		t.Fatalf("password change via alias created a parallel record, count=%d", records.NumRecords())
	}

	pr, ok := records.GetRecord("Alice")
	if !ok {
		t.Fatalf("canonical record missing")
	}
	if err := pr.ValidatePassword("newpassword"); err != nil {
		t.Fatalf("canonical record was not updated: %v", err)
	}
	if len(pr.Aliases) != 1 || pr.Aliases[0] != "al" {
		t.Fatalf("alias lost after password rotation: %v", pr.Aliases)
	}

	// The alias still resolves and the old password is rejected.
	pr, _, ok = records.GetCanonicalRecord("al")
	if !ok {
		t.Fatalf("alias no longer resolves after password rotation")
	}
	if err := pr.ValidatePassword("password"); err == nil {
		t.Fatalf("old password still valid after rotation")
	}
}

func TestRemoveAlias(t *testing.T) {
	records := newAliasVault(t)

	if err := records.AddAlias("Alice", "al"); err != nil {
		t.Fatalf("AddAlias failed: %v", err)
	}
	if err := records.RemoveAlias("al", "al"); err != nil {
		t.Fatalf("RemoveAlias failed: %v", err)
	}
	if _, ok := records.CanonicalName("al"); ok {
		t.Fatalf("removed alias still resolves")
	}
	if _, ok := records.CanonicalName("Alice"); !ok {
		t.Fatalf("canonical name was removed with the alias")
	}
}

func TestLoadClosesAliasConflicts(t *testing.T) {
	tmpf, err := ioutil.TempFile("", "ro_alias")
	if err != nil {
		t.Fatalf("%v", err)
	}
	path := tmpf.Name()
	tmpf.Close()
	defer os.Remove(path)

	// Simulate an on-disk vault where two records claim the same
	// alias (e.g. written by an older build). Loading must leave a
	// single, unambiguous owner.
	records, err := InitFrom(path)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if _, err = records.AddNewRecord("Alice", "password", true, RSARecord); err != nil {
		t.Fatalf("%v", err)
	}
	if _, err = records.AddNewRecord("Bob", "password", false, RSARecord); err != nil {
		t.Fatalf("%v", err)
	}
	if err := records.AddAlias("Alice", "shared"); err != nil {
		t.Fatalf("%v", err)
	}

	bob := records.Passwords["Bob"]
	bob.Aliases = []string{"shared"}
	records.Passwords["Bob"] = bob
	if err := records.WriteRecordsToDisk(); err != nil {
		t.Fatalf("%v", err)
	}

	reloaded, err := InitFrom(path)
	if err != nil {
		t.Fatalf("%v", err)
	}

	seen := make(map[string]string)
	for name, rec := range reloaded.Passwords {
		for _, alias := range rec.Aliases {
			if owner, dup := seen[alias]; dup {
				t.Fatalf("alias %q still ambiguous between %q and %q after load", alias, owner, name)
			}
			seen[alias] = name
			if _, shadowed := reloaded.Passwords[alias]; shadowed {
				t.Fatalf("alias %q still shadows a canonical name after load", alias)
			}
		}
	}

	canonical, ok := reloaded.CanonicalName("shared")
	if !ok {
		t.Fatalf("legacy alias stopped resolving")
	}
	if canonical != "Alice" {
		t.Fatalf("first (legacy) alias owner was not preserved, got %q", canonical)
	}

	// Both canonical accounts themselves remain usable.
	if _, ok := reloaded.CanonicalName("Alice"); !ok {
		t.Fatalf("Alice missing after load")
	}
	if _, ok := reloaded.CanonicalName("Bob"); !ok {
		t.Fatalf("Bob missing after load")
	}
}
