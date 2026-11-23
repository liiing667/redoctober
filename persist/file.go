package persist

import (
	"io/ioutil"
	"os"

	"github.com/cloudflare/redoctober/config"
	"github.com/cloudflare/redoctober/keycache"
	"github.com/cloudflare/redoctober/passvault"
)

// File implements a file-backed persistence store.
type File struct {
	config *config.Delegations
	cache  *keycache.Cache
	state  string
	blob   []byte
	// snapshotID identifies the snapshot currently held in blob.
	// It is set on load and refreshed whenever a new, complete
	// snapshot is persisted. Every consumer of the store therefore
	// shares a single snapshot identity.
	snapshotID string
}

// Valid ensures the configuration is valid for a file store. Note
// that it won't validate the policy, it will just ensure that one
// is present.
func (f *File) Valid() bool {
	if f.config.Persist == false {
		return false
	}

	if f.config.Policy == "" {
		return false
	}

	if len(f.config.Users) == 0 {
		return false
	}

	if f.config.Mechanism != FileMechanism {
		return false
	}

	if f.config.Location == "" {
		return false
	}

	return true
}

// newFile returns a new file-backed persistence store.
func newFile(config *config.Delegations) (Store, error) {
	cache := keycache.NewCache()
	file := &File{
		config: config,
		cache:  &cache,
		state:  Inactive,
	}

	if !file.Valid() {
		return nil, ErrInvalidConfig
	}

	err := file.Load()
	if err != nil {
		return nil, err
	}
	return file, nil
}

func (f *File) Blob() []byte {
	return f.blob
}

func (f *File) SnapshotID() string {
	return f.snapshotID
}

func (f *File) Policy() string {
	return f.config.Policy
}

func (f *File) Users() []string {
	return f.config.Users
}

func (f *File) Store(blob []byte) error {
	if f.state == Active {
		f.blob = blob
		if err := ioutil.WriteFile(f.config.Location, blob, 0644); err != nil {
			return err
		}
		// Only adopt the new snapshot identity once the complete
		// snapshot has landed on disk; a failed write leaves the
		// previous identity (and blob) intact.
		f.snapshotID = SnapshotIDFor(blob)
	}
	return nil
}

func (f *File) Load() error {
	if fi, err := os.Stat(f.config.Location); err != nil {
		// If the file doesn't exist, it can be persisted
		// immediately.
		if os.IsNotExist(err) {
			f.state = Active
			return nil
		}

		return err
	} else if fi.Size() == 0 {
		f.state = Active
		return nil
	}

	in, err := ioutil.ReadFile(f.config.Location)
	if err != nil {
		return err
	}

	f.state = Inactive
	f.blob = in
	f.snapshotID = SnapshotIDFor(in)
	return nil
}

func (f *File) Persist() {
	f.state = Active
}

func (f *File) Cache() *keycache.Cache {
	return f.cache
}

func (f *File) Delegate(record passvault.PasswordRecord, name, password string, users, labels []string, uses int, slot, durationString string) error {
	return f.cache.AddKeyFromRecordGeneration(record, name, password, users, labels, uses, slot, durationString, record.RevocationGeneration)
}

func (f *File) Status() *Status {
	return &Status{
		State:   f.state,
		Summary: f.cache.GetSummary(),
	}
}

func (f *File) Purge() error {
	f.state = Active
	f.blob = nil
	f.snapshotID = ""
	if err := os.Remove(f.config.Location); err != nil {
		return err
	}
	return nil
}
