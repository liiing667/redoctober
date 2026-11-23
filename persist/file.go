package persist

import (
	"bytes"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"github.com/cloudflare/redoctober/config"
	"github.com/cloudflare/redoctober/keycache"
	"github.com/cloudflare/redoctober/passvault"
)

// ErrCorruptStore is returned when the data read back from a newly
// written store file does not match the generation that was written.
// The previous, intact generation is retained both on disk and in
// memory when this happens.
var ErrCorruptStore = errors.New("persist: store file failed verification")

// File implements a file-backed persistence store.
type File struct {
	// lock serialises every operation that observes or mutates the
	// store generation (state, blob, and the file on disk). This
	// ensures a commit can never interleave with another commit,
	// a load, or a purge.
	lock   sync.Mutex
	config *config.Delegations
	cache  *keycache.Cache
	state  string
	// blob is the exact, verified content of the store file. It is
	// replaced only after a complete new generation has been
	// written and atomically installed, so it always describes the
	// same generation as the file on disk.
	blob []byte
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
	f.lock.Lock()
	defer f.lock.Unlock()

	// Return a snapshot so callers cannot mutate the live
	// generation while it is being written or read.
	if len(f.blob) == 0 {
		return nil
	}
	return append([]byte(nil), f.blob...)
}

func (f *File) Policy() string {
	return f.config.Policy
}

func (f *File) Users() []string {
	return f.config.Users
}

func (f *File) Store(blob []byte) error {
	f.lock.Lock()
	defer f.lock.Unlock()

	if f.state != Active {
		return nil
	}

	return f.commitLocked(blob)
}

func (f *File) Load() error {
	f.lock.Lock()
	defer f.lock.Unlock()

	in, err := ioutil.ReadFile(f.config.Location)
	if err != nil {
		// If the file doesn't exist, this is a legitimate first
		// run and the store can persist immediately.
		if os.IsNotExist(err) {
			f.state = Active
			f.blob = nil
			return nil
		}

		// Don't disturb the currently known generation when the
		// file cannot be read.
		return err
	}

	// An existing, empty file carries no generation. It is the
	// legitimate first-run state (for example, a file created
	// ahead of the server) and is safe to start persisting from.
	if len(in) == 0 {
		f.state = Active
		f.blob = nil
		return nil
	}

	// A non-empty file is an existing generation that must be
	// restored before persistence resumes. Publish the state and
	// the full blob together so all consumers see one generation.
	f.state = Inactive
	f.blob = in
	return nil
}

func (f *File) Persist() {
	f.lock.Lock()
	defer f.lock.Unlock()
	f.state = Active
}

func (f *File) Cache() *keycache.Cache {
	return f.cache
}

func (f *File) Delegate(record passvault.PasswordRecord, name, password string, users, labels []string, uses int, slot, durationString string) error {
	return f.cache.AddKeyFromRecord(record, name, password, users, labels, uses, slot, durationString)
}

func (f *File) Status() *Status {
	f.lock.Lock()
	defer f.lock.Unlock()

	return &Status{
		State:   f.state,
		Summary: f.cache.GetSummary(),
	}
}

func (f *File) Purge() error {
	f.lock.Lock()
	defer f.lock.Unlock()

	if err := os.Remove(f.config.Location); err != nil {
		// A missing file is already the desired end state, so
		// purging a store that was never written (or already
		// purged) is not an error.
		if !os.IsNotExist(err) {
			// Preserve the old generation if it could not be
			// removed.
			return err
		}
	}

	f.state = Active
	f.blob = nil
	return nil
}

// commitLocked durably writes a new generation of the store. The
// caller must hold f.lock.
//
// The data is written to a temporary file in the same directory,
// synced, read back and verified, and only then atomically renamed
// over the live file. If any step fails, the live file and f.blob are
// left untouched, so the previous generation remains available and a
// retry cannot mix content from two writes.
func (f *File) commitLocked(blob []byte) error {
	// Take a snapshot of the caller's data so later mutation of the
	// input cannot change what is verified or what becomes live.
	data := append([]byte(nil), blob...)

	dir := filepath.Dir(f.config.Location)
	tmp, err := ioutil.TempFile(dir, ".redoctober-persist-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	cleanup := func() {
		tmp.Close()
		os.Remove(tmpName)
	}

	n, err := tmp.Write(data)
	if err != nil {
		cleanup()
		return err
	}
	if n != len(data) {
		cleanup()
		return ErrCorruptStore
	}

	// Make sure the complete generation reaches stable storage
	// before it becomes visible under the live name.
	if err = tmp.Sync(); err != nil {
		cleanup()
		return err
	}

	if err = tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}

	// Verify the whole generation landed intact before replacing
	// the old file.
	written, err := ioutil.ReadFile(tmpName)
	if err != nil {
		os.Remove(tmpName)
		return err
	}
	if !bytes.Equal(written, data) {
		os.Remove(tmpName)
		return ErrCorruptStore
	}

	if err = os.Rename(tmpName, f.config.Location); err != nil {
		os.Remove(tmpName)
		return err
	}

	// Advance the in-memory generation only after the new file is
	// durably in place. On every failure above the old blob (and
	// the old file) are retained unchanged.
	f.blob = data
	return nil
}

// SetLocation overrides the on-disk location of a file store. It is
// intended for tests that need to simulate write failures against an
// otherwise valid store.
func (f *File) SetLocation(location string) {
	f.lock.Lock()
	defer f.lock.Unlock()
	f.config.Location = location
}

// Location returns the current on-disk location of a file store.
func (f *File) Location() string {
	f.lock.Lock()
	defer f.lock.Unlock()
	return f.config.Location
}
