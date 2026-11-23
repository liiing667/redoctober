// Package persist implements delegation persistence. It is primarily
// concerned with configuration and serialisation; encryption and
// decryption is done by the cryptor package.
package persist

import (
	"errors"

	"github.com/cloudflare/redoctober/config"
	"github.com/cloudflare/redoctober/keycache"
	"github.com/cloudflare/redoctober/passvault"
)

var defaultStore Store = &File{}

// Snapshot is the versioned envelope that is encrypted and written
// to a persistence store. Together with the content-derived identity
// the store computes over its encrypted bytes (see SnapshotIDFor),
// the version and revocation generation carried here let start-up
// loading, an explicit restore, expiry/revocation checks and
// consumer recovery all reason about the exact same snapshot rather
// than a loose blob of bytes.
type Snapshot struct {
	// Version is the snapshot envelope format version.
	Version int
	// Generation is the vault-wide revocation generation captured
	// when the snapshot was persisted.
	Generation uint64
	// Cache is the serialised key cache summary.
	Cache map[string]keycache.ActiveUser
}

// SnapshotVersion is the current Snapshot envelope version.
const SnapshotVersion = 1

// Labels are the labels that the keycache should be encrypted with.
var Labels = []string{"restore"}

// Usages indicate whether encrypted data can be decrypted or only used for signing
var Usages = []string{}

const (
	// Disabled indicates that the persistence store will never
	// persist active delegations.
	Disabled = "disabled"

	// Inactive indicates that the persistence store requires
	// more delegations to unlock, and isn't currently persisting
	// the store.
	Inactive = "inactive"

	// Active indicates that the persistence store is
	// actively persisting delegations.
	Active = "active"
)

// Status contains information on the current status of a persistence
// store.
type Status struct {
	State   string `json:"state"`
	Summary map[string]keycache.ActiveUser
}

// Store is a persistence store interface that handles delegations,
// serialising the persistence store, and writing the store to disk.
type Store interface {
	Blob() []byte
	// SnapshotID returns the identity of the snapshot currently
	// held by the store. It is empty when no snapshot has been
	// loaded or persisted yet.
	SnapshotID() string
	Policy() string
	Users() []string
	Store([]byte) error
	Load() error
	Status() *Status
	// Persist tells the Store to start actively persisting.
	Persist()
	Delegate(record passvault.PasswordRecord, name, password string, users, labels []string, uses int, slot, durationString string) error
	// This is not the main keycache. This is the keycache for
	// users that can decrypt the store.
	Cache() *keycache.Cache
	// Purge clears the persisted keys.
	Purge() error
}

// FileMechanism indicates that the persistence mechanism is a file.
const FileMechanism = "file"

type mechanism func(*config.Delegations) (Store, error)

var stores = map[string]mechanism{
	"":            newNull,
	FileMechanism: newFile,
}

// New attempts to create a new persistence store from the
// configuration.
func New(config *config.Delegations) (Store, error) {
	if config == nil {
		return nil, errors.New("persist: nil configuration")
	}

	if !config.Persist {
		return newNull(config)
	}

	constructor, ok := stores[config.Mechanism]
	if !ok {
		return nil, errors.New("persist: invalid persistence mechanism")
	}

	return constructor(config)
}

// ErrInvalidConfig is returned when the configuration is invalid for
// the type of persistence store in use.
var ErrInvalidConfig = errors.New("persist: invalid configuration")
