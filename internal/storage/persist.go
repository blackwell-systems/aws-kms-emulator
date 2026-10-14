// persist.go lets the emulator keep its state on disk, so keys survive a
// restart. It is opt-in: without Config.DataDir the store stays in memory.
//
// The whole state is rewritten after every successful change. The file is
// replaced atomically (write a temp file, then rename), so a crash leaves
// either the previous state or the new one, never a partial file.
//
// The state file holds private key material in plaintext. It is created with
// 0600 permissions and must only ever contain development keys.
package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// StateFileName is the name of the file the state is kept in, inside the data directory.
const StateFileName = "state.json"

// snapshotFormatVersion is bumped whenever the on-disk layout changes incompatibly.
const snapshotFormatVersion = 1

type snapshot struct {
	FormatVersion int             `json:"formatVersion"`
	Keys          []snapshotKey   `json:"keys"`
	Aliases       []snapshotAlias `json:"aliases"`
}

type snapshotKey struct {
	ID                  string            `json:"id"`
	Spec                KeySpec           `json:"spec"`
	Usage               KeyUsage          `json:"usage"`
	State               KeyState          `json:"state"`
	Description         string            `json:"description,omitempty"`
	CreationDate        time.Time         `json:"creationDate"`
	DeletionDate        time.Time         `json:"deletionDate,omitzero"`
	PendingWindowInDays int               `json:"pendingWindowInDays,omitempty"`
	Tags                map[string]string `json:"tags,omitempty"`
	PrivateKey          []byte            `json:"privateKey,omitempty"`
}

type snapshotAlias struct {
	Name        string    `json:"name"`
	TargetKeyID string    `json:"targetKeyId"`
	Created     time.Time `json:"created"`
	Updated     time.Time `json:"updated"`
}

func (s *Store) statePath() string { return filepath.Join(s.cfg.DataDir, StateFileName) }

// load restores the state file. A missing file is an empty state; a file that
// exists but cannot be read or parsed is an error, so a damaged file is never
// silently overwritten.
func (s *Store) load() error {
	data, err := os.ReadFile(s.statePath())
	if errors.Is(err, fs.ErrNotExist) {
		return os.MkdirAll(s.cfg.DataDir, 0o700)
	}
	if err != nil {
		return fmt.Errorf("reading state file: %w", err)
	}
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("parsing %s: %w", s.statePath(), err)
	}
	if snap.FormatVersion != snapshotFormatVersion {
		return fmt.Errorf("%s has format version %d; this build reads version %d", s.statePath(), snap.FormatVersion, snapshotFormatVersion)
	}
	for _, sk := range snap.Keys {
		k := &key{
			id: sk.ID, spec: sk.Spec, usage: sk.Usage, state: sk.State,
			description: sk.Description, creationDate: sk.CreationDate,
			deletionDate: sk.DeletionDate, pendingWindow: sk.PendingWindowInDays,
			tags: sk.Tags,
		}
		if k.tags == nil {
			k.tags = map[string]string{}
		}
		if len(sk.PrivateKey) > 0 {
			if k.mat, err = unmarshalMaterial(sk.Spec, sk.PrivateKey); err != nil {
				return fmt.Errorf("restoring key %s: %w", sk.ID, err)
			}
			if k.publicDER, err = k.mat.publicKeyDER(); err != nil {
				return fmt.Errorf("restoring key %s: %w", sk.ID, err)
			}
		}
		s.keys[k.id] = k
	}
	for _, sa := range snap.Aliases {
		s.aliases[sa.Name] = &alias{name: sa.Name, targetKeyID: sa.TargetKeyID, created: sa.Created, updated: sa.Updated}
	}
	return nil
}

// saveLocked rewrites the state file. It is a no-op without a data directory.
// Callers hold s.mu.
func (s *Store) saveLocked() error {
	if s.cfg.DataDir == "" {
		return nil
	}
	snap := snapshot{FormatVersion: snapshotFormatVersion}
	for _, k := range s.keys {
		sk := snapshotKey{
			ID: k.id, Spec: k.spec, Usage: k.usage, State: k.state,
			Description: k.description, CreationDate: k.creationDate,
			DeletionDate: k.deletionDate, PendingWindowInDays: k.pendingWindow,
			Tags: k.tags,
		}
		if k.mat != nil {
			der, err := k.mat.marshalPrivate()
			if err != nil {
				return newErr(CodeInternal, "persisting key %s: %v", k.id, err)
			}
			sk.PrivateKey = der
		}
		snap.Keys = append(snap.Keys, sk)
	}
	sort.Slice(snap.Keys, func(i, j int) bool { return snap.Keys[i].ID < snap.Keys[j].ID })
	for _, a := range s.aliases {
		snap.Aliases = append(snap.Aliases, snapshotAlias{Name: a.name, TargetKeyID: a.targetKeyID, Created: a.created, Updated: a.updated})
	}
	sort.Slice(snap.Aliases, func(i, j int) bool { return snap.Aliases[i].Name < snap.Aliases[j].Name })

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return newErr(CodeInternal, "persisting state: %v", err)
	}
	if err := writeFileAtomic(s.statePath(), data); err != nil {
		return newErr(CodeInternal, "persisting state: %v", err)
	}
	return nil
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), StateFileName+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
