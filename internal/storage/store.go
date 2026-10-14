// Package storage holds the emulator's KMS keys, aliases and tags, and the
// cryptographic operations on them. It is the only place that knows what AWS
// KMS accepts and rejects; the server package only translates HTTP and JSON.
package storage

import (
	"crypto/rand"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Defaults for the account and Region that appear in key ARNs.
const (
	DefaultRegion    = "us-east-1"
	DefaultAccountID = "111122223333"
)

// Config configures a Store.
type Config struct {
	// Region and AccountID appear in every ARN. Defaults: DefaultRegion and
	// DefaultAccountID.
	Region    string
	AccountID string
	// DataDir, when set, makes the store restore its state from state.json in
	// that directory and rewrite it after every change.
	DataDir string
	// Now returns the current time. Default: time.Now. Tests use it to move
	// past a key's deletion date.
	Now func() time.Time
}

type key struct {
	id            string
	spec          KeySpec
	usage         KeyUsage
	state         KeyState
	description   string
	creationDate  time.Time
	deletionDate  time.Time
	pendingWindow int
	tags          map[string]string
	mat           *material // nil for symmetric keys, which hold no material in this emulator
	publicDER     []byte
}

type alias struct {
	name        string // including the "alias/" prefix
	targetKeyID string
	created     time.Time
	updated     time.Time
}

// Store is the in-memory (optionally persisted) KMS state for one account and
// Region. It is safe for concurrent use.
type Store struct {
	mu      sync.Mutex
	cfg     Config
	keys    map[string]*key
	aliases map[string]*alias
}

// New returns a Store. If cfg.DataDir is set it restores the state saved there.
func New(cfg Config) (*Store, error) {
	if cfg.Region == "" {
		cfg.Region = DefaultRegion
	}
	if cfg.AccountID == "" {
		cfg.AccountID = DefaultAccountID
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Store{cfg: cfg, keys: map[string]*key{}, aliases: map[string]*alias{}}
	if cfg.DataDir != "" {
		if err := s.load(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// KeyARN returns the ARN of the key with the given ID.
func (s *Store) KeyARN(id string) string {
	return fmt.Sprintf("arn:aws:kms:%s:%s:key/%s", s.cfg.Region, s.cfg.AccountID, id)
}

func (s *Store) aliasARN(name string) string {
	return fmt.Sprintf("arn:aws:kms:%s:%s:%s", s.cfg.Region, s.cfg.AccountID, name)
}

// Metadata is the KeyMetadata of a KMS key.
type Metadata struct {
	KeyID               string
	ARN                 string
	AccountID           string
	Spec                KeySpec
	Usage               KeyUsage
	State               KeyState
	Description         string
	CreationDate        time.Time
	DeletionDate        time.Time // zero unless State is PendingDeletion
	PendingWindowInDays int       // zero unless State is PendingDeletion
	SigningAlgorithms   []SigningAlgorithm
	EncryptionAlgs      []string
}

func (s *Store) metadata(k *key) Metadata {
	m := Metadata{
		KeyID: k.id, ARN: s.KeyARN(k.id), AccountID: s.cfg.AccountID,
		Spec: k.spec, Usage: k.usage, State: k.state, Description: k.description,
		CreationDate: k.creationDate,
	}
	if k.state == StatePendingDeletion {
		m.DeletionDate = k.deletionDate
		m.PendingWindowInDays = k.pendingWindow
	}
	if k.usage == UsageSignVerify {
		m.SigningAlgorithms = append(m.SigningAlgorithms, signingAlgorithms[k.spec]...)
	}
	if k.usage == UsageEncryptDecrypt && k.spec == SpecSymmetricDefault {
		m.EncryptionAlgs = []string{"SYMMETRIC_DEFAULT"}
	}
	return m
}

// Tag is a key tag.
type Tag struct{ Key, Value string }

// CreateKeyParams are the CreateKey inputs the emulator uses. Spec and Usage
// are empty when the request omitted them.
type CreateKeyParams struct {
	Spec        string
	Usage       string
	Description string
	Tags        []Tag
}

// CreateKey creates a KMS key.
func (s *Store) CreateKey(p CreateKeyParams) (Metadata, error) {
	spec, usage := KeySpec(p.Spec), KeyUsage(p.Usage)
	if spec == "" {
		spec = SpecSymmetricDefault
	}
	if len(p.Description) > 8192 {
		return Metadata{}, newErr(CodeValidation, "1 validation error detected: Value at 'description' failed to satisfy constraint: Member must have length less than or equal to 8192")
	}
	if !knownSpecs[spec] {
		return Metadata{}, newErr(CodeValidation, "1 validation error detected: Value '%s' at 'keySpec' failed to satisfy constraint: Member must satisfy enum value set", spec)
	}
	if usage != "" && !knownUsages[usage] {
		return Metadata{}, newErr(CodeValidation, "1 validation error detected: Value '%s' at 'keyUsage' failed to satisfy constraint: Member must satisfy enum value set", usage)
	}
	if usage == "" {
		if spec != SpecSymmetricDefault {
			return Metadata{}, newErr(CodeValidation, "You must specify a KeyUsage value for all KMS keys except for symmetric encryption keys.")
		}
		usage = UsageEncryptDecrypt
	}
	if err := checkSpecUsage(spec, usage); err != nil {
		return Metadata{}, err
	}
	if err := validateTags(p.Tags, 0); err != nil {
		return Metadata{}, err
	}

	var mat *material
	var pub []byte
	if spec != SpecSymmetricDefault {
		var err error
		if mat, err = generateMaterial(spec); err != nil {
			return Metadata{}, newErr(CodeInternal, "key generation failed: %v", err)
		}
		if pub, err = mat.publicKeyDER(); err != nil {
			return Metadata{}, newErr(CodeInternal, "encoding the public key failed: %v", err)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapLocked()
	k := &key{
		id: newUUID(), spec: spec, usage: usage, state: StateEnabled,
		description: p.Description, creationDate: s.cfg.Now(),
		tags: map[string]string{}, mat: mat, publicDER: pub,
	}
	for _, t := range p.Tags {
		k.tags[t.Key] = t.Value
	}
	s.keys[k.id] = k
	if err := s.saveLocked(); err != nil {
		return Metadata{}, err
	}
	return s.metadata(k), nil
}

// checkSpecUsage rejects KeySpec/KeyUsage combinations AWS does not allow, and
// valid combinations the emulator does not implement.
func checkSpecUsage(spec KeySpec, usage KeyUsage) error {
	valid := false
	switch spec {
	case SpecSymmetricDefault:
		valid = usage == UsageEncryptDecrypt
	case SpecRSA2048, SpecRSA3072, SpecRSA4096:
		valid = usage == UsageSignVerify || usage == UsageEncryptDecrypt
	case SpecECCNISTP256, SpecECCNISTP384, SpecECCNISTP521:
		valid = usage == UsageSignVerify || usage == "KEY_AGREEMENT"
	case SpecECCSECGP256K1, SpecEd25519:
		valid = usage == UsageSignVerify
	case "HMAC_224", "HMAC_256", "HMAC_384", "HMAC_512":
		valid = usage == "GENERATE_VERIFY_MAC"
	case "ML_DSA_44", "ML_DSA_65", "ML_DSA_87":
		valid = usage == UsageSignVerify
	case "SM2":
		return newErr(CodeUnsupportedOperation, "KeySpec SM2 is available only in China Regions")
	}
	if !valid {
		return newErr(CodeValidation, "KeyUsage %s is not compatible with KeySpec %s", usage, spec)
	}
	if spec == SpecSymmetricDefault || usage == UsageSignVerify && signingAlgorithms[spec] != nil {
		return nil
	}
	return newErr(CodeUnsupportedOperation, "KeySpec %s with KeyUsage %s is not supported by aws-kms-emulator", spec, usage)
}

// resolve finds the key a KeyId names. KeyId may be a key ID, a key ARN, an
// alias name or an alias ARN; aliases are accepted only when allowAlias is set,
// as AWS documents for each operation. Callers hold s.mu.
func (s *Store) resolve(keyID string, allowAlias bool) (*key, error) {
	id := keyID
	if strings.HasPrefix(keyID, "arn:") {
		parts := strings.SplitN(keyID, ":", 6)
		if len(parts) != 6 || parts[2] != "kms" || parts[1] == "" {
			return nil, newErr(CodeInvalidArn, "Invalid arn %s", keyID)
		}
		resource := parts[5]
		if !strings.HasPrefix(resource, "key/") && !strings.HasPrefix(resource, "alias/") {
			return nil, newErr(CodeInvalidArn, "Invalid arn %s", keyID)
		}
		if parts[3] != s.cfg.Region || parts[4] != s.cfg.AccountID {
			if strings.HasPrefix(resource, "alias/") {
				return nil, newErr(CodeNotFound, "Alias %s is not found.", keyID)
			}
			return nil, newErr(CodeNotFound, "Key '%s' does not exist", keyID)
		}
		id = resource
	}
	if strings.HasPrefix(id, "alias/") && allowAlias {
		a, ok := s.aliases[id]
		if !ok {
			return nil, newErr(CodeNotFound, "Alias %s is not found.", s.aliasARN(id))
		}
		id = a.targetKeyID
	}
	id = strings.TrimPrefix(id, "key/")
	k, ok := s.keys[id]
	if !ok {
		return nil, newErr(CodeNotFound, "Key '%s' does not exist", s.KeyARN(id))
	}
	return k, nil
}

// reapLocked deletes keys (and their aliases) whose deletion date has passed.
func (s *Store) reapLocked() {
	now := s.cfg.Now()
	changed := false
	for id, k := range s.keys {
		if k.state == StatePendingDeletion && !now.Before(k.deletionDate) {
			delete(s.keys, id)
			for name, a := range s.aliases {
				if a.targetKeyID == id {
					delete(s.aliases, name)
				}
			}
			changed = true
		}
	}
	if changed {
		_ = s.saveLocked() // the deletion is already in memory; the next change retries the write
	}
}

// DescribeKey returns the metadata of a key.
func (s *Store) DescribeKey(keyID string) (Metadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapLocked()
	k, err := s.resolve(keyID, true)
	if err != nil {
		return Metadata{}, err
	}
	return s.metadata(k), nil
}

// PublicKey is the GetPublicKey result.
type PublicKey struct {
	KeyARN            string
	Spec              KeySpec
	Usage             KeyUsage
	DER               []byte
	SigningAlgorithms []SigningAlgorithm
}

// GetPublicKey returns the public key of an asymmetric key.
func (s *Store) GetPublicKey(keyID string) (PublicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapLocked()
	k, err := s.resolve(keyID, true)
	if err != nil {
		return PublicKey{}, err
	}
	arn := s.KeyARN(k.id)
	if k.state == StatePendingDeletion {
		return PublicKey{}, newErr(CodeInvalidState, "%s is pending deletion.", arn)
	}
	if k.mat == nil {
		return PublicKey{}, newErr(CodeUnsupportedOperation, "%s is a symmetric key; GetPublicKey requires an asymmetric KMS key.", arn)
	}
	pk := PublicKey{KeyARN: arn, Spec: k.spec, Usage: k.usage, DER: k.publicDER}
	if k.usage == UsageSignVerify {
		pk.SigningAlgorithms = append(pk.SigningAlgorithms, signingAlgorithms[k.spec]...)
	}
	return pk, nil
}

// SignParams are the inputs of Sign and Verify. MessageType is empty when the
// request omitted it, which AWS treats as RAW.
type SignParams struct {
	KeyID       string
	Message     []byte
	MessageType string
	Algorithm   string
	Signature   []byte // Verify only
}

// SignResult is the Sign result.
type SignResult struct {
	KeyARN    string
	Signature []byte
	Algorithm SigningAlgorithm
}

// prepareSign resolves the key and applies every rule Sign and Verify share,
// in the order AWS checks them: key existence, key state, key usage, algorithm
// against key spec, then message type and length.
func (s *Store) prepareSign(op string, p SignParams) (*key, string, SigningAlgorithm, MessageType, error) {
	alg, mt := SigningAlgorithm(p.Algorithm), MessageType(p.MessageType)
	if mt == "" {
		mt = MessageRaw
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapLocked()
	k, err := s.resolve(p.KeyID, true)
	if err != nil {
		return nil, "", "", "", err
	}
	arn := s.KeyARN(k.id)
	switch k.state {
	case StateDisabled:
		return nil, "", "", "", newErr(CodeDisabled, "%s is disabled.", arn)
	case StatePendingDeletion:
		return nil, "", "", "", newErr(CodeInvalidState, "%s is pending deletion.", arn)
	}
	if k.usage != UsageSignVerify || k.mat == nil {
		return nil, "", "", "", newErr(CodeInvalidKeyUsage, "%s key usage is %s which is not valid for %s.", arn, k.usage, op)
	}
	if !supportsAlgorithm(k.spec, alg) {
		return nil, "", "", "", newErr(CodeInvalidKeyUsage, "Algorithm %s is incompatible with key spec %s.", alg, k.spec)
	}
	if err := checkMessage(alg, mt, p.Message); err != nil {
		return nil, "", "", "", err
	}
	return k, arn, alg, mt, nil
}

// checkMessage applies the MessageType rules: ED25519_SHA_512 requires RAW,
// ED25519_PH_SHA_512 requires DIGEST, EXTERNAL_MU is for ML-DSA only, and a
// DIGEST must be exactly as long as the algorithm's hash.
func checkMessage(alg SigningAlgorithm, mt MessageType, msg []byte) error {
	switch {
	case mt == MessageExternalMu:
		return newErr(CodeValidation, "MessageType EXTERNAL_MU is valid only with ML-DSA signing algorithms.")
	case alg == AlgEd25519 && mt != MessageRaw:
		return newErr(CodeValidation, "Algorithm %s requires MessageType RAW.", alg)
	case alg == AlgEd25519ph && mt != MessageDigest:
		return newErr(CodeValidation, "Algorithm %s requires MessageType DIGEST.", alg)
	case mt == MessageDigest && len(msg) != algHash(alg).Size():
		return newErr(CodeValidation, "Digest is invalid length for algorithm %s.", alg)
	}
	return nil
}

// Sign signs a message or digest with an asymmetric SIGN_VERIFY key.
func (s *Store) Sign(p SignParams) (SignResult, error) {
	k, arn, alg, mt, err := s.prepareSign("Sign", p)
	if err != nil {
		return SignResult{}, err
	}
	sig, err := k.mat.sign(alg, mt, p.Message) // key material is immutable; no lock needed
	if err != nil {
		return SignResult{}, newErr(CodeInternal, "signing failed: %v", err)
	}
	return SignResult{KeyARN: arn, Signature: sig, Algorithm: alg}, nil
}

// Verify checks a signature. A signature that does not verify is a
// KMSInvalidSignatureException error, as in AWS; success returns the key ARN.
func (s *Store) Verify(p SignParams) (SignResult, error) {
	k, arn, alg, mt, err := s.prepareSign("Verify", p)
	if err != nil {
		return SignResult{}, err
	}
	if !k.mat.verify(alg, mt, p.Message, p.Signature) {
		return SignResult{}, newErr(CodeInvalidSignature, "Signature verification failed.")
	}
	return SignResult{KeyARN: arn, Algorithm: alg}, nil
}

// ListKeys returns one page of keys ordered by key ID. limit 0 means the AWS
// default of 100.
func (s *Store) ListKeys(limit int, marker string) (keys []Metadata, next string, err error) {
	if limit == 0 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapLocked()
	after, err := decodeMarker(marker)
	if err != nil {
		return nil, "", err
	}
	ids := make([]string, 0, len(s.keys))
	for id := range s.keys {
		if id > after {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	truncated := len(ids) > limit
	if truncated {
		ids = ids[:limit]
	}
	for _, id := range ids {
		keys = append(keys, s.metadata(s.keys[id]))
	}
	if truncated {
		next = encodeMarker(ids[len(ids)-1])
	}
	return keys, next, nil
}

// setEnabled implements EnableKey and DisableKey. Both succeed on a key that
// is already in the target state and fail on a key pending deletion.
func (s *Store) setEnabled(keyID string, enabled bool) error {
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
	k.state = StateDisabled
	if enabled {
		k.state = StateEnabled
	}
	return s.saveLocked()
}

// EnableKey enables a key.
func (s *Store) EnableKey(keyID string) error { return s.setEnabled(keyID, true) }

// DisableKey disables a key.
func (s *Store) DisableKey(keyID string) error { return s.setEnabled(keyID, false) }

// ScheduleDeletionResult is the ScheduleKeyDeletion result.
type ScheduleDeletionResult struct {
	KeyARN       string
	DeletionDate time.Time
	WindowInDays int
}

// ScheduleKeyDeletion puts a key in PendingDeletion. windowDays 0 means the
// default of 30; otherwise it must be 7 to 30. Once the window has passed the
// key, its aliases and its tags are gone.
func (s *Store) ScheduleKeyDeletion(keyID string, windowDays int) (ScheduleDeletionResult, error) {
	if windowDays == 0 {
		windowDays = 30
	}
	if windowDays < 7 || windowDays > 30 {
		return ScheduleDeletionResult{}, newErr(CodeValidation, "1 validation error detected: Value '%d' at 'pendingWindowInDays' failed to satisfy constraint: Member must have value between 7 and 30", windowDays)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapLocked()
	k, err := s.resolve(keyID, false)
	if err != nil {
		return ScheduleDeletionResult{}, err
	}
	arn := s.KeyARN(k.id)
	if k.state == StatePendingDeletion {
		return ScheduleDeletionResult{}, newErr(CodeInvalidState, "%s is pending deletion.", arn)
	}
	k.state = StatePendingDeletion
	k.pendingWindow = windowDays
	k.deletionDate = s.cfg.Now().Add(time.Duration(windowDays) * 24 * time.Hour)
	if err := s.saveLocked(); err != nil {
		return ScheduleDeletionResult{}, err
	}
	return ScheduleDeletionResult{KeyARN: arn, DeletionDate: k.deletionDate, WindowInDays: windowDays}, nil
}

// CancelKeyDeletion returns a PendingDeletion key to Disabled and gives its ARN.
func (s *Store) CancelKeyDeletion(keyID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapLocked()
	k, err := s.resolve(keyID, false)
	if err != nil {
		return "", err
	}
	arn := s.KeyARN(k.id)
	if k.state != StatePendingDeletion {
		return "", newErr(CodeInvalidState, "%s is not pending deletion.", arn)
	}
	k.state = StateDisabled
	k.deletionDate = time.Time{}
	k.pendingWindow = 0
	if err := s.saveLocked(); err != nil {
		return "", err
	}
	return arn, nil
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
