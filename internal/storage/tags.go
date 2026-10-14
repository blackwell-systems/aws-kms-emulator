package storage

import (
	"sort"
	"strings"
)

// MaxTagsPerKey is the number of tags AWS allows on one resource.
const MaxTagsPerKey = 50

// validateTags checks tags being added to a key that already has existing of
// them. Tags that replace an existing key do not count against the limit.
func validateTags(tags []Tag, existing int) error {
	seen := map[string]bool{}
	for _, t := range tags {
		if len(t.Key) < 1 || len(t.Key) > 128 {
			return newErr(CodeValidation, "1 validation error detected: Value at 'tags.tagKey' failed to satisfy constraint: Member must have length between 1 and 128")
		}
		if len(t.Value) > 256 {
			return newErr(CodeValidation, "1 validation error detected: Value at 'tags.tagValue' failed to satisfy constraint: Member must have length less than or equal to 256")
		}
		if strings.HasPrefix(strings.ToLower(t.Key), "aws:") {
			return newErr(CodeTag, "Tags beginning with aws: are reserved for AWS use.")
		}
		if seen[t.Key] {
			return newErr(CodeTag, "Duplicate tag keys are not allowed: %s", t.Key)
		}
		seen[t.Key] = true
	}
	if existing+len(tags) > MaxTagsPerKey {
		return newErr(CodeLimitExceeded, "A key can have at most %d tags.", MaxTagsPerKey)
	}
	return nil
}

// TagResource adds tags to a key, replacing the value of tags that exist.
func (s *Store) TagResource(keyID string, tags []Tag) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapLocked()
	k, err := s.resolve(keyID, false)
	if err != nil {
		return err
	}
	if k.state == StatePendingDeletion {
		return newErr(CodeInvalidState, "%s is pending deletion.", s.KeyARN(k.id))
	}
	added := 0
	for _, t := range tags {
		if _, ok := k.tags[t.Key]; !ok {
			added++
		}
	}
	if err := validateTags(tags, len(k.tags)-(len(tags)-added)); err != nil {
		return err
	}
	for _, t := range tags {
		k.tags[t.Key] = t.Value
	}
	return s.saveLocked()
}

// UntagResource removes tags by key. Keys the key does not have are ignored.
func (s *Store) UntagResource(keyID string, tagKeys []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapLocked()
	k, err := s.resolve(keyID, false)
	if err != nil {
		return err
	}
	if k.state == StatePendingDeletion {
		return newErr(CodeInvalidState, "%s is pending deletion.", s.KeyARN(k.id))
	}
	for _, name := range tagKeys {
		delete(k.tags, name)
	}
	return s.saveLocked()
}

// ListResourceTags returns one page of a key's tags ordered by tag key. limit
// 0 means the AWS default of 50. It works on keys in any state.
func (s *Store) ListResourceTags(keyID string, limit int, marker string) (out []Tag, next string, err error) {
	if limit == 0 {
		limit = 50
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapLocked()
	k, err := s.resolve(keyID, false)
	if err != nil {
		return nil, "", err
	}
	after, err := decodeMarker(marker)
	if err != nil {
		return nil, "", err
	}
	names := make([]string, 0, len(k.tags))
	for name := range k.tags {
		if name > after {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	truncated := len(names) > limit
	if truncated {
		names = names[:limit]
	}
	for _, name := range names {
		out = append(out, Tag{Key: name, Value: k.tags[name]})
	}
	if truncated {
		next = encodeMarker(names[len(names)-1])
	}
	return out, next, nil
}
