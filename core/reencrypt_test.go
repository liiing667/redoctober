// reencrypt_test.go: acceptance tests for re-encryption key rotation.
//
// Copyright (c) 2013 CloudFlare, Inc.

package core

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	"github.com/cloudflare/redoctober/config"
)

func ownersOf(t *testing.T, data []byte) OwnersData {
	resp, err := Owners(mustMarshal(t, OwnersRequest{Data: data}))
	if err != nil {
		t.Fatalf("owners request: %v", err)
	}
	var out OwnersData
	if err = json.Unmarshal(resp, &out); err != nil {
		t.Fatalf("owners response: %v", err)
	}
	if out.Status != "ok" {
		t.Fatalf("owners status: %s", out.Status)
	}
	return out
}

func mustMarshal(t *testing.T, in interface{}) []byte {
	out, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

// TestReEncryptKeepsSourceOwners verifies end to end through the core
// handlers that a re-encryption request which omits the access structure
// still produces a ciphertext with exactly the source owners, predicate
// and labels.  This is the wrap-key rotation use case.
func TestReEncryptKeepsSourceOwners(t *testing.T) {
	cfg := config.New()
	Init("memory", cfg)

	mustOk(t, Create([]byte(`{"Name":"Alice","Password":"Hello"}`)))
	mustOk(t, Delegate([]byte(`{"Name":"Bob","Password":"Hello","Time":"1h","Uses":10}`)))
	mustOk(t, Delegate([]byte(`{"Name":"Carol","Password":"Hello","Time":"1h","Uses":10}`)))

	encryptResp := encryptForTest(t, EncryptRequest{
		Name:     "Carol",
		Password: "Hello",
		Minimum:  2,
		Owners:   []string{"Alice", "Bob", "Carol"},
		Labels:   []string{"blue"},
		Data:     []byte("Hello Jello"),
	})

	sourceInfo := ownersOf(t, encryptResp.Response)

	// Rotation request: no owners, predicate or labels are repeated.
	reResp := reEncryptForTest(t, ReEncryptRequest{
		Name:     "Alice",
		Password: "Hello",
		Data:     encryptResp.Response,
	})

	outputInfo := ownersOf(t, reResp.Response)

	sort.Strings(sourceInfo.Owners)
	sort.Strings(outputInfo.Owners)
	if !reflect.DeepEqual(sourceInfo.Owners, outputInfo.Owners) {
		t.Fatalf("Owners differ after re-encryption: source=%v output=%v",
			sourceInfo.Owners, outputInfo.Owners)
	}

	sort.Strings(sourceInfo.Labels)
	sort.Strings(outputInfo.Labels)
	if !reflect.DeepEqual(sourceInfo.Labels, outputInfo.Labels) {
		t.Fatalf("Labels differ after re-encryption: source=%v output=%v",
			sourceInfo.Labels, outputInfo.Labels)
	}

	if sourceInfo.Predicate != outputInfo.Predicate {
		t.Fatalf("Predicate differs after re-encryption: source=%q output=%q",
			sourceInfo.Predicate, outputInfo.Predicate)
	}

	// The rotated ciphertext must still decrypt to the original data.
	decResp, err := Decrypt(mustMarshal(t, DecryptRequest{
		Name:     "Alice",
		Password: "Hello",
		Data:     reResp.Response,
	}))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	var status ResponseData
	if err = json.Unmarshal(decResp, &status); err != nil {
		t.Fatalf("decrypt response: %v", err)
	}
	if status.Status != "ok" {
		t.Fatalf("decrypt status: %s", status.Status)
	}
	var d DecryptWithDelegates
	if err = json.Unmarshal(status.Response, &d); err != nil {
		t.Fatalf("decrypt payload: %v", err)
	}
	if string(d.Data) != "Hello Jello" {
		t.Fatalf("plaintext mismatch: %q", d.Data)
	}
}

// TestReEncryptKeepsSourcePredicateAndNoLabels covers predicate-based
// ciphertexts and ciphertexts that were created without labels.
func TestReEncryptKeepsSourcePredicateAndNoLabels(t *testing.T) {
	cfg := config.New()
	Init("memory", cfg)

	mustOk(t, Create([]byte(`{"Name":"Alice","Password":"Hello"}`)))
	mustOk(t, Delegate([]byte(`{"Name":"Bob","Password":"Hello","Time":"1h","Uses":10}`)))
	mustOk(t, Delegate([]byte(`{"Name":"Carol","Password":"Hello","Time":"1h","Uses":10}`)))

	encryptResp := encryptForTest(t, EncryptRequest{
		Name:      "Carol",
		Password:  "Hello",
		Predicate: "(2, (1, Alice, Bob), Carol)",
		Data:      []byte("predicate secret"),
	})

	sourceInfo := ownersOf(t, encryptResp.Response)
	if sourceInfo.Predicate == "" {
		t.Fatalf("source predicate missing")
	}
	if len(sourceInfo.Labels) != 0 {
		t.Fatalf("source should have no labels, got %v", sourceInfo.Labels)
	}

	reResp := reEncryptForTest(t, ReEncryptRequest{
		Name:     "Alice",
		Password: "Hello",
		Data:     encryptResp.Response,
	})

	outputInfo := ownersOf(t, reResp.Response)
	if outputInfo.Predicate != sourceInfo.Predicate {
		t.Fatalf("predicate lost in re-encryption: source=%q output=%q",
			sourceInfo.Predicate, outputInfo.Predicate)
	}
	if len(outputInfo.Labels) != 0 {
		t.Fatalf("re-encrypted ciphertext gained labels: %v", outputInfo.Labels)
	}

	sort.Strings(sourceInfo.Owners)
	sort.Strings(outputInfo.Owners)
	if !reflect.DeepEqual(sourceInfo.Owners, outputInfo.Owners) {
		t.Fatalf("Owners differ after predicate re-encryption: source=%v output=%v",
			sourceInfo.Owners, outputInfo.Owners)
	}
}

func mustOk(t *testing.T, raw []byte) {
	var s ResponseData
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("response decode: %v", err)
	}
	if s.Status != "ok" {
		t.Fatalf("unexpected status %q", s.Status)
	}
}

func encryptForTest(t *testing.T, req EncryptRequest) ResponseData {
	raw, err := Encrypt(mustMarshal(t, req))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	var s ResponseData
	if err = json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("encrypt response: %v", err)
	}
	if s.Status != "ok" {
		t.Fatalf("encrypt status: %s", s.Status)
	}
	return s
}

func reEncryptForTest(t *testing.T, req ReEncryptRequest) ResponseData {
	raw, err := ReEncrypt(mustMarshal(t, req))
	if err != nil {
		t.Fatalf("re-encrypt: %v", err)
	}
	var s ResponseData
	if err = json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("re-encrypt response: %v", err)
	}
	if s.Status != "ok" {
		t.Fatalf("re-encrypt status: %s", s.Status)
	}
	return s
}
