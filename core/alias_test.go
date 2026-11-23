// alias_test.go: end-to-end tests for canonical identity handling
// when accounts are addressed through aliases.
//
// Copyright (c) 2013 CloudFlare, Inc.

package core

import (
	"encoding/json"
	"testing"

	"github.com/cloudflare/redoctober/config"
)

func initAliasVault(t *testing.T) {
	cfg := config.New()
	Init("memory", cfg)

	resp, err := Create([]byte(`{"Name":"Alice","Password":"Hello"}`))
	if err != nil {
		t.Fatalf("vault create failed: %v", err)
	}
	var s ResponseData
	if err = json.Unmarshal(resp, &s); err != nil || s.Status != "ok" {
		t.Fatalf("vault create bad response: %v %s", err, s.Status)
	}
}

func TestCreateUserWithAlias(t *testing.T) {
	initAliasVault(t)

	// A user created with aliases must be addressable both by the
	// canonical name and every alias.
	resp, err := CreateUser([]byte(`{"Name":"Bill","Password":"Lizard","Aliases":["bill-alias","b"]}`))
	if err != nil {
		t.Fatalf("create-user with aliases failed: %v", err)
	}
	var s ResponseData
	if err = json.Unmarshal(resp, &s); err != nil || s.Status != "ok" {
		t.Fatalf("create-user bad response: %v %s", err, s.Status)
	}

	for _, name := range []string{"Bill", "bill-alias", "b"} {
		if err := validateUser(name, "Lizard", false); err != nil {
			t.Fatalf("authentication as %q failed: %v", name, err)
		}
	}

	// Summary is keyed by the canonical name and carries the aliases.
	summaryResp, err := Summary([]byte(`{"Name":"Alice","Password":"Hello"}`))
	if err != nil {
		t.Fatalf("summary failed: %v", err)
	}
	var summary SummaryData
	if err = json.Unmarshal(summaryResp, &summary); err != nil {
		t.Fatalf("summary decode failed: %v", err)
	}
	bill, ok := summary.All["Bill"]
	if !ok {
		t.Fatalf("canonical user missing from summary")
	}
	if len(bill.Aliases) != 2 {
		t.Fatalf("expected 2 aliases in summary, got %v", bill.Aliases)
	}
	if _, present := summary.All["bill-alias"]; present {
		t.Fatalf("alias leaked into summary as a separate identity")
	}
}

func TestCreateUserRejectsConflictingAlias(t *testing.T) {
	initAliasVault(t)

	if resp, err := CreateUser([]byte(`{"Name":"Bill","Password":"Lizard","Aliases":["shared"]}`)); err != nil {
		t.Fatalf("first create-user failed: %v", err)
	} else {
		var s ResponseData
		json.Unmarshal(resp, &s)
		if s.Status != "ok" {
			t.Fatalf("first create-user bad status: %s", s.Status)
		}
	}

	// A second account claiming the same alias is rejected and no
	// record is created.
	resp, err := CreateUser([]byte(`{"Name":"Cat","Password":"Cheshire","Aliases":["shared"]}`))
	if err != nil {
		t.Fatalf("second create-user failed: %v", err)
	}
	var s ResponseData
	json.Unmarshal(resp, &s)
	if s.Status == "ok" {
		t.Fatalf("conflicting alias was accepted")
	}

	if _, ok := records.GetRecord("Cat"); ok {
		t.Fatalf("rejected create-user still committed a record")
	}

	// The original owner keeps sole possession of the alias.
	canonical, ok := records.CanonicalName("shared")
	if !ok || canonical != "Bill" {
		t.Fatalf("alias ownership is ambiguous, resolved to %q ok=%v", canonical, ok)
	}
}

func TestPasswordRotationViaAlias(t *testing.T) {
	initAliasVault(t)

	resp, _ := CreateUser([]byte(`{"Name":"Bill","Password":"Lizard","Aliases":["bill-alias"]}`))
	var s ResponseData
	json.Unmarshal(resp, &s)
	if s.Status != "ok" {
		t.Fatalf("create-user bad status: %s", s.Status)
	}

	// Rotate the password by authenticating with the alias. The
	// change must land on the canonical record.
	resp, err := Password([]byte(`{"Name":"bill-alias","Password":"Lizard","NewPassword":"Kraken"}`))
	if err != nil {
		t.Fatalf("password via alias failed: %v", err)
	}
	json.Unmarshal(resp, &s)
	if s.Status != "ok" {
		t.Fatalf("password via alias bad status: %s", s.Status)
	}

	if records.NumRecords() != 2 {
		t.Fatalf("rotation via alias created parallel identity, count=%d", records.NumRecords())
	}

	// New password works under both names; the old one is rejected.
	if err := validateUser("Bill", "Kraken", false); err != nil {
		t.Fatalf("canonical auth with new password failed: %v", err)
	}
	if err := validateUser("bill-alias", "Kraken", false); err != nil {
		t.Fatalf("alias auth with new password failed: %v", err)
	}
	if err := validateUser("Bill", "Lizard", false); err == nil {
		t.Fatalf("old password still accepted")
	}
}

func TestDelegateAndDecryptViaAlias(t *testing.T) {
	initAliasVault(t)

	// Alice is the vault admin with alias "al".
	resp, err := AddAlias([]byte(`{"Name":"Alice","Password":"Hello","Alias":"al"}`))
	if err != nil {
		t.Fatalf("add-alias failed: %v", err)
	}
	var s ResponseData
	json.Unmarshal(resp, &s)
	if s.Status != "ok" {
		t.Fatalf("add-alias bad status: %s", s.Status)
	}

	resp, _ = CreateUser([]byte(`{"Name":"Bob","Password":"Rob","Aliases":["bob"]}`))
	json.Unmarshal(resp, &s)
	if s.Status != "ok" {
		t.Fatalf("create-user bad status: %s", s.Status)
	}

	// Delegate using the alias; the live cache must key the
	// delegation under the canonical name.
	resp, err = Delegate([]byte(`{"Name":"al","Password":"Hello","Time":"2h","Uses":10,"Users":["bob"]}`))
	if err != nil {
		t.Fatalf("delegate via alias failed: %v", err)
	}
	json.Unmarshal(resp, &s)
	if s.Status != "ok" {
		t.Fatalf("delegate via alias bad status: %s", s.Status)
	}

	live := crypt.LiveSummary()
	if _, ok := live["Alice"]; !ok {
		t.Fatalf("delegation not stored under canonical name, live=%v", live)
	}
	if _, ok := live["al"]; ok {
		t.Fatalf("delegation stored under alias, identity split")
	}

	// Encrypt to Alice, then decrypt by addressing the delegated
	// user with the alias.
	encResp, err := Encrypt([]byte(`{"Name":"Alice","Password":"Hello","Minimum":1,"Owners":["Alice"],"Data":"SGVsbG8gSmVsbG8="}`))
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	var encData ResponseData
	if err = json.Unmarshal(encResp, &encData); err != nil || encData.Status != "ok" {
		t.Fatalf("encrypt bad response: %v %s", err, encData.Status)
	}

	decResp, err := Decrypt([]byte(`{"Name":"bob","Password":"Rob","Data":` + string(encData.Response) + `}`))
	if err != nil {
		t.Fatalf("decrypt via alias failed: %v", err)
	}
	var dec DecryptWithDelegates
	var decEnvelope ResponseData
	json.Unmarshal(decResp, &decEnvelope)
	if decEnvelope.Status != "ok" {
		t.Fatalf("decrypt via alias bad status: %s", decEnvelope.Status)
	}
	if err = json.Unmarshal(decEnvelope.Response, &dec); err != nil {
		t.Fatalf("decrypt decode failed: %v", err)
	}
	if string(dec.Data) != "Hello Jello" {
		t.Fatalf("decrypted payload mismatch: %q", dec.Data)
	}

	// The reported delegate must be the canonical name, never the
	// alias used to authenticate.
	foundCanonical := false
	for _, name := range dec.Delegates {
		if name == "al" {
			t.Fatalf("alias reported as delegate: %v", dec.Delegates)
		}
		if name == "Alice" {
			foundCanonical = true
		}
	}
	if !foundCanonical {
		t.Fatalf("canonical delegate missing from report: %v", dec.Delegates)
	}
}

func TestAddRemoveAliasEndpoints(t *testing.T) {
	initAliasVault(t)

	resp, _ := CreateUser([]byte(`{"Name":"Bill","Password":"Lizard"}`))
	var s ResponseData
	json.Unmarshal(resp, &s)

	resp, err := AddAlias([]byte(`{"Name":"Bill","Password":"Lizard","Alias":"bill-alias"}`))
	if err != nil {
		t.Fatalf("add-alias failed: %v", err)
	}
	json.Unmarshal(resp, &s)
	if s.Status != "ok" {
		t.Fatalf("add-alias bad status: %s", s.Status)
	}

	if err := validateUser("bill-alias", "Lizard", false); err != nil {
		t.Fatalf("auth through new alias failed: %v", err)
	}

	// Wrong password cannot manage aliases.
	resp, _ = AddAlias([]byte(`{"Name":"Bill","Password":"wrong","Alias":"x"}`))
	json.Unmarshal(resp, &s)
	if s.Status == "ok" {
		t.Fatalf("add-alias accepted bad password")
	}

	resp, err = RemoveAlias([]byte(`{"Name":"bill-alias","Password":"Lizard","Alias":"bill-alias"}`))
	if err != nil {
		t.Fatalf("remove-alias failed: %v", err)
	}
	json.Unmarshal(resp, &s)
	if s.Status != "ok" {
		t.Fatalf("remove-alias bad status: %s", s.Status)
	}

	if _, ok := records.CanonicalName("bill-alias"); ok {
		t.Fatalf("alias still resolves after removal")
	}
	if err := validateUser("Bill", "Lizard", false); err != nil {
		t.Fatalf("canonical account broke on alias removal: %v", err)
	}
}

func TestDelegateUnknownNameStillCreatesOneAccount(t *testing.T) {
	initAliasVault(t)

	// A genuinely unknown delegation name keeps the legacy behaviour
	// of auto-creating exactly one account.
	resp, err := Delegate([]byte(`{"Name":"Newbie","Password":"pw","Time":"1h","Uses":1}`))
	if err != nil {
		t.Fatalf("delegate auto-create failed: %v", err)
	}
	var s ResponseData
	json.Unmarshal(resp, &s)
	if s.Status != "ok" {
		t.Fatalf("delegate auto-create bad status: %s", s.Status)
	}
	if records.NumRecords() != 2 {
		t.Fatalf("expected vault admin plus one new account, count=%d", records.NumRecords())
	}
	canonical, ok := records.CanonicalName("Newbie")
	if !ok || canonical != "Newbie" {
		t.Fatalf("auto-created account not canonical, got %q", canonical)
	}

	// Re-delegating through the same name does not duplicate the
	// identity.
	resp, err = Delegate([]byte(`{"Name":"Newbie","Password":"pw","Time":"1h","Uses":1}`))
	if err != nil {
		t.Fatalf("second delegate failed: %v", err)
	}
	json.Unmarshal(resp, &s)
	if s.Status != "ok" {
		t.Fatalf("second delegate bad status: %s", s.Status)
	}
	if records.NumRecords() != 2 {
		t.Fatalf("re-delegation created a parallel account, count=%d", records.NumRecords())
	}
}
