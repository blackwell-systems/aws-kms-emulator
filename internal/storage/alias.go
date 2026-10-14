package storage

import (
	"encoding/base64"
	"regexp"
	"sort"
	"strings"
	"time"
)

// MaxAliasesPerKey is the AWS default quota of aliases per KMS key.
const MaxAliasesPerKey = 50

var aliasNamePattern = regexp.MustCompile(`^alias/[a-zA-Z0-9/_-]+$`)

func checkAliasName(name string) error {
	if len(name) > 256 {
		return newErr(CodeValidation, "1 validation error detected: Value at 'aliasName' failed to satisfy constraint: Member must have length less than or equal to 256")
	}
	if !aliasNamePattern.MatchString(name) {
		return newErr(CodeInvalidAliasName, "%s is not a valid alias name. An alias name must begin with alias/ and contain only alphanumeric characters, slashes, underscores and dashes.", name)
	}
	if strings.HasPrefix(name, "alias/aws/") {
		return newErr(CodeInvalidAliasName, "Alias names cannot begin with alias/aws/; that prefix is reserved for AWS managed keys.")
	}
	return nil
}

// targetKey resolves the TargetKeyId of CreateAlias and UpdateAlias, which
// AWS documents as a key ID or key ARN, and requires it not to be pending
// deletion. Callers hold s.mu.
func (s *Store) targetKey(targetKeyID string) (*key, error) {
	k, err := s.resolve(targetKeyID, false)
	if err != nil {
		return nil, err
	}
	if k.state == StatePendingDeletion {
		return nil, newErr(CodeInvalidState, "%s is pending deletion.", s.KeyARN(k.id))
	}
	return k, nil
}

func (s *Store) aliasCountLocked(keyID string) int {
	n := 0
	for _, a := range s.aliases {
		if a.targetKeyID == keyID {
			n++
		}
	}
	return n
}

// CreateAlias adds an alias for a key.
func (s *Store) CreateAlias(name, targetKeyID string) error {
	if err := checkAliasName(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapLocked()
	k, err := s.targetKey(targetKeyID)
	if err != nil {
		return err
	}
	if _, exists := s.aliases[name]; exists {
		return newErr(CodeAlreadyExists, "An alias with the name %s already exists", s.aliasARN(name))
	}
	if s.aliasCountLocked(k.id) >= MaxAliasesPerKey {
		return newErr(CodeLimitExceeded, "%s already has the maximum of %d aliases.", s.KeyARN(k.id), MaxAliasesPerKey)
	}
	now := s.cfg.Now()
	s.aliases[name] = &alias{name: name, targetKeyID: k.id, created: now, updated: now}
	return s.saveLocked()
}

// UpdateAlias points an existing alias at another key.
func (s *Store) UpdateAlias(name, targetKeyID string) error {
	if err := checkAliasName(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapLocked()
	a, ok := s.aliases[name]
	if !ok {
		return newErr(CodeNotFound, "Alias %s is not found.", s.aliasARN(name))
	}
	k, err := s.targetKey(targetKeyID)
	if err != nil {
		return err
	}
	if k.id != a.targetKeyID && s.aliasCountLocked(k.id) >= MaxAliasesPerKey {
		return newErr(CodeLimitExceeded, "%s already has the maximum of %d aliases.", s.KeyARN(k.id), MaxAliasesPerKey)
	}
	a.targetKeyID = k.id
	a.updated = s.cfg.Now()
	return s.saveLocked()
}

// DeleteAlias removes an alias. The key it pointed at is unaffected.
func (s *Store) DeleteAlias(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapLocked()
	if _, ok := s.aliases[name]; !ok {
		return newErr(CodeNotFound, "Alias %s is not found.", s.aliasARN(name))
	}
	delete(s.aliases, name)
	return s.saveLocked()
}

// AliasEntry is one ListAliases result.
type AliasEntry struct {
	ARN         string
	Name        string
	TargetKeyID string
	Created     time.Time
	Updated     time.Time
}

// ListAliases returns one page of aliases ordered by name, optionally only
// those of one key. limit 0 means the AWS default of 50.
func (s *Store) ListAliases(keyID string, limit int, marker string) (out []AliasEntry, next string, err error) {
	if limit == 0 {
		limit = 50
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapLocked()
	filter := ""
	if keyID != "" {
		k, err := s.resolve(keyID, false)
		if err != nil {
			return nil, "", err
		}
		filter = k.id
	}
	after, err := decodeMarker(marker)
	if err != nil {
		return nil, "", err
	}
	names := make([]string, 0, len(s.aliases))
	for name, a := range s.aliases {
		if name > after && (filter == "" || a.targetKeyID == filter) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	truncated := len(names) > limit
	if truncated {
		names = names[:limit]
	}
	for _, name := range names {
		a := s.aliases[name]
		out = append(out, AliasEntry{
			ARN: s.aliasARN(name), Name: name, TargetKeyID: a.targetKeyID,
			Created: a.created, Updated: a.updated,
		})
	}
	if truncated {
		next = encodeMarker(names[len(names)-1])
	}
	return out, next, nil
}

// A marker is the sort key of the last item of the previous page. AWS tells
// callers not to construct one; the emulator rejects any it cannot decode.
func encodeMarker(last string) string { return base64.RawURLEncoding.EncodeToString([]byte(last)) }

func decodeMarker(marker string) (string, error) {
	if marker == "" {
		return "", nil
	}
	b, err := base64.RawURLEncoding.DecodeString(marker)
	if err != nil {
		return "", newErr(CodeInvalidMarker, "The marker is not valid.")
	}
	return string(b), nil
}
