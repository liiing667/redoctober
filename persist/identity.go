package persist

import (
	"crypto/sha256"
	"encoding/hex"
)

// SnapshotIDFor derives the identity of a snapshot from the exact
// bytes that were loaded or persisted. Because it is a content hash
// it needs no decryption, it is identical before and after a
// restart, and a new, complete snapshot naturally gets a new
// identity. Start-up loading, explicit restores, expiry/revocation
// checks and consumer recovery therefore all share one identity: as
// long as the on-disk bytes are untouched, SnapshotIDFor returns the
// same ID. An empty blob has the empty identity.
func SnapshotIDFor(blob []byte) string {
	if len(blob) == 0 {
		return ""
	}
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:])
}
