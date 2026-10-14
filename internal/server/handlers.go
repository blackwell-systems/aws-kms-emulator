package server

import (
	"fmt"
	"time"

	"github.com/blackwell-systems/aws-kms-emulator/internal/storage"
)

func validation(format string, args ...any) error {
	return &storage.Error{Code: storage.CodeValidation, Message: fmt.Sprintf(format, args...)}
}

// requireString applies the "required, length 1 to max" constraint AWS puts on
// identifiers such as KeyId.
func requireString(field, value string, max int) error {
	if value == "" {
		return validation("1 validation error detected: Value null at '%s' failed to satisfy constraint: Member must not be null", field)
	}
	if len(value) > max {
		return validation("1 validation error detected: Value at '%s' failed to satisfy constraint: Member must have length less than or equal to %d", field, max)
	}
	return nil
}

// requireBlob applies the "required, 1 to max bytes" constraint on blobs.
func requireBlob(field string, value []byte, max int) error {
	if len(value) == 0 {
		return validation("1 validation error detected: Value at '%s' failed to satisfy constraint: Member must have length greater than or equal to 1", field)
	}
	if len(value) > max {
		return validation("1 validation error detected: Value at '%s' failed to satisfy constraint: Member must have length less than or equal to %d", field, max)
	}
	return nil
}

// checkPaging validates the Limit and Marker of a List operation and returns
// the limit, which is 0 when the request left it out.
func checkPaging(limit *int, marker string, max int) (int, error) {
	if marker != "" && len(marker) > 1024 {
		return 0, validation("1 validation error detected: Value at 'marker' failed to satisfy constraint: Member must have length less than or equal to 1024")
	}
	if limit == nil {
		return 0, nil
	}
	if *limit < 1 || *limit > max {
		return 0, validation("1 validation error detected: Value '%d' at 'limit' failed to satisfy constraint: Member must have value between 1 and %d", *limit, max)
	}
	return *limit, nil
}

// epoch renders a time the way the AWS JSON protocol does: seconds since the
// epoch, with a fractional part.
func epoch(t time.Time) float64 { return float64(t.UnixMilli()) / 1000 }

type tag struct {
	TagKey   string `json:"TagKey"`
	TagValue string `json:"TagValue"`
}

func toStorageTags(in []tag) []storage.Tag {
	out := make([]storage.Tag, len(in))
	for i, t := range in {
		out[i] = storage.Tag{Key: t.TagKey, Value: t.TagValue}
	}
	return out
}

// keyMetadata is the KeyMetadata shape of CreateKey and DescribeKey.
type keyMetadata struct {
	AWSAccountId                string   `json:"AWSAccountId"`
	Arn                         string   `json:"Arn"`
	CreationDate                float64  `json:"CreationDate"`
	CustomerMasterKeySpec       string   `json:"CustomerMasterKeySpec"`
	DeletionDate                *float64 `json:"DeletionDate,omitempty"`
	Description                 string   `json:"Description"`
	Enabled                     bool     `json:"Enabled"`
	EncryptionAlgorithms        []string `json:"EncryptionAlgorithms,omitempty"`
	KeyId                       string   `json:"KeyId"`
	KeyManager                  string   `json:"KeyManager"`
	KeySpec                     string   `json:"KeySpec"`
	KeyState                    string   `json:"KeyState"`
	KeyUsage                    string   `json:"KeyUsage"`
	MultiRegion                 bool     `json:"MultiRegion"`
	Origin                      string   `json:"Origin"`
	PendingDeletionWindowInDays int      `json:"PendingDeletionWindowInDays,omitempty"`
	SigningAlgorithms           []string `json:"SigningAlgorithms,omitempty"`
}

func toKeyMetadata(m storage.Metadata) keyMetadata {
	km := keyMetadata{
		AWSAccountId: m.AccountID, Arn: m.ARN, CreationDate: epoch(m.CreationDate),
		CustomerMasterKeySpec: string(m.Spec), Description: m.Description,
		Enabled: m.State == storage.StateEnabled, EncryptionAlgorithms: m.EncryptionAlgs,
		KeyId: m.KeyID, KeyManager: "CUSTOMER", KeySpec: string(m.Spec),
		KeyState: string(m.State), KeyUsage: string(m.Usage), Origin: "AWS_KMS",
		PendingDeletionWindowInDays: m.PendingWindowInDays,
	}
	if !m.DeletionDate.IsZero() {
		d := epoch(m.DeletionDate)
		km.DeletionDate = &d
	}
	for _, a := range m.SigningAlgorithms {
		km.SigningAlgorithms = append(km.SigningAlgorithms, string(a))
	}
	return km
}

type createKeyRequest struct {
	BypassPolicyLockoutSafetyCheck bool   `json:"BypassPolicyLockoutSafetyCheck"`
	CustomerMasterKeySpec          string `json:"CustomerMasterKeySpec"`
	CustomKeyStoreId               string `json:"CustomKeyStoreId"`
	Description                    string `json:"Description"`
	KeySpec                        string `json:"KeySpec"`
	KeyUsage                       string `json:"KeyUsage"`
	MultiRegion                    bool   `json:"MultiRegion"`
	Origin                         string `json:"Origin"`
	Policy                         string `json:"Policy"`
	Tags                           []tag  `json:"Tags"`
	XksKeyId                       string `json:"XksKeyId"`
}

type keyMetadataResponse struct {
	KeyMetadata keyMetadata `json:"KeyMetadata"`
}

func unsupported(format string, args ...any) error {
	return &storage.Error{Code: storage.CodeUnsupportedOperation, Message: fmt.Sprintf(format, args...)}
}

func (s *Server) createKey(req *createKeyRequest) (*keyMetadataResponse, error) {
	spec := req.KeySpec
	if req.CustomerMasterKeySpec != "" {
		// KeySpec and the deprecated CustomerMasterKeySpec are the same parameter.
		if spec != "" && spec != req.CustomerMasterKeySpec {
			return nil, validation("You cannot specify KeySpec and CustomerMasterKeySpec in the same request.")
		}
		spec = req.CustomerMasterKeySpec
	}
	if req.MultiRegion {
		return nil, unsupported("Multi-Region keys are not supported by aws-kms-emulator.")
	}
	if req.Origin != "" && req.Origin != "AWS_KMS" {
		return nil, unsupported("Origin %s is not supported by aws-kms-emulator; only AWS_KMS is.", req.Origin)
	}
	if req.CustomKeyStoreId != "" || req.XksKeyId != "" {
		return nil, unsupported("Custom key stores are not supported by aws-kms-emulator.")
	}
	if req.Policy != "" && len(req.Policy) > 32768 {
		return nil, &storage.Error{Code: storage.CodeLimitExceeded, Message: "The key policy exceeds the maximum length of 32768 characters."}
	}
	m, err := s.store.CreateKey(storage.CreateKeyParams{
		Spec: spec, Usage: req.KeyUsage, Description: req.Description, Tags: toStorageTags(req.Tags),
	})
	if err != nil {
		return nil, err
	}
	return &keyMetadataResponse{KeyMetadata: toKeyMetadata(m)}, nil
}

type keyIDRequest struct {
	KeyId string `json:"KeyId"`
}

func (s *Server) describeKey(req *keyIDRequest) (*keyMetadataResponse, error) {
	if err := requireString("keyId", req.KeyId, 2048); err != nil {
		return nil, err
	}
	m, err := s.store.DescribeKey(req.KeyId)
	if err != nil {
		return nil, err
	}
	return &keyMetadataResponse{KeyMetadata: toKeyMetadata(m)}, nil
}

type getPublicKeyResponse struct {
	CustomerMasterKeySpec string   `json:"CustomerMasterKeySpec"`
	KeyId                 string   `json:"KeyId"`
	KeySpec               string   `json:"KeySpec"`
	KeyUsage              string   `json:"KeyUsage"`
	PublicKey             []byte   `json:"PublicKey"`
	SigningAlgorithms     []string `json:"SigningAlgorithms,omitempty"`
}

func (s *Server) getPublicKey(req *keyIDRequest) (*getPublicKeyResponse, error) {
	if err := requireString("keyId", req.KeyId, 2048); err != nil {
		return nil, err
	}
	pk, err := s.store.GetPublicKey(req.KeyId)
	if err != nil {
		return nil, err
	}
	resp := &getPublicKeyResponse{
		CustomerMasterKeySpec: string(pk.Spec), KeyId: pk.KeyARN, KeySpec: string(pk.Spec),
		KeyUsage: string(pk.Usage), PublicKey: pk.DER,
	}
	for _, a := range pk.SigningAlgorithms {
		resp.SigningAlgorithms = append(resp.SigningAlgorithms, string(a))
	}
	return resp, nil
}

type signRequest struct {
	DryRun           bool     `json:"DryRun"`
	GrantTokens      []string `json:"GrantTokens"`
	KeyId            string   `json:"KeyId"`
	Message          []byte   `json:"Message"`
	MessageType      string   `json:"MessageType"`
	SigningAlgorithm string   `json:"SigningAlgorithm"`
}

type signResponse struct {
	KeyId            string `json:"KeyId"`
	Signature        []byte `json:"Signature"`
	SigningAlgorithm string `json:"SigningAlgorithm"`
}

// checkSignFields applies the request-shape rules shared by Sign and Verify:
// they hold before any key is looked at, so they win over every key error.
func checkSignFields(keyID string, message []byte, messageType, algorithm string) error {
	if err := requireString("keyId", keyID, 2048); err != nil {
		return err
	}
	if err := requireBlob("message", message, storage.MaxMessageSize); err != nil {
		return err
	}
	if algorithm == "" {
		return validation("1 validation error detected: Value null at 'signingAlgorithm' failed to satisfy constraint: Member must not be null")
	}
	if !storage.IsKnownSigningAlgorithm(algorithm) {
		return validation("1 validation error detected: Value '%s' at 'signingAlgorithm' failed to satisfy constraint: Member must satisfy enum value set", algorithm)
	}
	if messageType != "" && !storage.IsKnownMessageType(messageType) {
		return validation("1 validation error detected: Value '%s' at 'messageType' failed to satisfy constraint: Member must satisfy enum value set", messageType)
	}
	if algorithm == "SM2DSA" || algorithm == "ML_DSA_SHAKE_256" {
		return unsupported("SigningAlgorithm %s is not supported by aws-kms-emulator.", algorithm)
	}
	return nil
}

func (s *Server) sign(req *signRequest) (*signResponse, error) {
	if err := checkSignFields(req.KeyId, req.Message, req.MessageType, req.SigningAlgorithm); err != nil {
		return nil, err
	}
	res, err := s.store.Sign(storage.SignParams{
		KeyID: req.KeyId, Message: req.Message, MessageType: req.MessageType, Algorithm: req.SigningAlgorithm,
	})
	if err != nil {
		return nil, err
	}
	return &signResponse{KeyId: res.KeyARN, Signature: res.Signature, SigningAlgorithm: string(res.Algorithm)}, nil
}

type verifyRequest struct {
	DryRun           bool     `json:"DryRun"`
	GrantTokens      []string `json:"GrantTokens"`
	KeyId            string   `json:"KeyId"`
	Message          []byte   `json:"Message"`
	MessageType      string   `json:"MessageType"`
	Signature        []byte   `json:"Signature"`
	SigningAlgorithm string   `json:"SigningAlgorithm"`
}

type verifyResponse struct {
	KeyId            string `json:"KeyId"`
	SignatureValid   bool   `json:"SignatureValid"`
	SigningAlgorithm string `json:"SigningAlgorithm"`
}

func (s *Server) verify(req *verifyRequest) (*verifyResponse, error) {
	if err := checkSignFields(req.KeyId, req.Message, req.MessageType, req.SigningAlgorithm); err != nil {
		return nil, err
	}
	if err := requireBlob("signature", req.Signature, 6144); err != nil {
		return nil, err
	}
	res, err := s.store.Verify(storage.SignParams{
		KeyID: req.KeyId, Message: req.Message, MessageType: req.MessageType,
		Algorithm: req.SigningAlgorithm, Signature: req.Signature,
	})
	if err != nil {
		return nil, err
	}
	return &verifyResponse{KeyId: res.KeyARN, SignatureValid: true, SigningAlgorithm: string(res.Algorithm)}, nil
}

type listRequest struct {
	KeyId  string `json:"KeyId"`
	Limit  *int   `json:"Limit"`
	Marker string `json:"Marker"`
}

type keyListEntry struct {
	KeyArn string `json:"KeyArn"`
	KeyId  string `json:"KeyId"`
}

type listKeysResponse struct {
	Keys       []keyListEntry `json:"Keys"`
	NextMarker string         `json:"NextMarker,omitempty"`
	Truncated  bool           `json:"Truncated"`
}

func (s *Server) listKeys(req *listRequest) (*listKeysResponse, error) {
	limit, err := checkPaging(req.Limit, req.Marker, 1000)
	if err != nil {
		return nil, err
	}
	keys, next, err := s.store.ListKeys(limit, req.Marker)
	if err != nil {
		return nil, err
	}
	resp := &listKeysResponse{Keys: []keyListEntry{}, NextMarker: next, Truncated: next != ""}
	for _, k := range keys {
		resp.Keys = append(resp.Keys, keyListEntry{KeyArn: k.ARN, KeyId: k.KeyID})
	}
	return resp, nil
}

func (s *Server) enableKey(req *keyIDRequest) (*struct{}, error) {
	if err := requireString("keyId", req.KeyId, 2048); err != nil {
		return nil, err
	}
	return nil, s.store.EnableKey(req.KeyId)
}

func (s *Server) disableKey(req *keyIDRequest) (*struct{}, error) {
	if err := requireString("keyId", req.KeyId, 2048); err != nil {
		return nil, err
	}
	return nil, s.store.DisableKey(req.KeyId)
}

type scheduleKeyDeletionRequest struct {
	KeyId               string `json:"KeyId"`
	PendingWindowInDays *int   `json:"PendingWindowInDays"`
}

type scheduleKeyDeletionResponse struct {
	DeletionDate        float64 `json:"DeletionDate"`
	KeyId               string  `json:"KeyId"`
	KeyState            string  `json:"KeyState"`
	PendingWindowInDays int     `json:"PendingWindowInDays"`
}

func (s *Server) scheduleKeyDeletion(req *scheduleKeyDeletionRequest) (*scheduleKeyDeletionResponse, error) {
	if err := requireString("keyId", req.KeyId, 2048); err != nil {
		return nil, err
	}
	window := 0 // storage reads 0 as the default of 30 days
	if req.PendingWindowInDays != nil {
		window = *req.PendingWindowInDays
		if window < 7 || window > 30 {
			return nil, validation("1 validation error detected: Value '%d' at 'pendingWindowInDays' failed to satisfy constraint: Member must have value between 7 and 30", window)
		}
	}
	res, err := s.store.ScheduleKeyDeletion(req.KeyId, window)
	if err != nil {
		return nil, err
	}
	return &scheduleKeyDeletionResponse{
		DeletionDate: epoch(res.DeletionDate), KeyId: res.KeyARN,
		KeyState: string(storage.StatePendingDeletion), PendingWindowInDays: res.WindowInDays,
	}, nil
}

type cancelKeyDeletionResponse struct {
	KeyId string `json:"KeyId"`
}

func (s *Server) cancelKeyDeletion(req *keyIDRequest) (*cancelKeyDeletionResponse, error) {
	if err := requireString("keyId", req.KeyId, 2048); err != nil {
		return nil, err
	}
	arn, err := s.store.CancelKeyDeletion(req.KeyId)
	if err != nil {
		return nil, err
	}
	return &cancelKeyDeletionResponse{KeyId: arn}, nil
}

type aliasRequest struct {
	AliasName   string `json:"AliasName"`
	TargetKeyId string `json:"TargetKeyId"`
}

func (r *aliasRequest) check() error {
	if err := requireString("aliasName", r.AliasName, 256); err != nil {
		return err
	}
	return requireString("targetKeyId", r.TargetKeyId, 2048)
}

func (s *Server) createAlias(req *aliasRequest) (*struct{}, error) {
	if err := req.check(); err != nil {
		return nil, err
	}
	return nil, s.store.CreateAlias(req.AliasName, req.TargetKeyId)
}

func (s *Server) updateAlias(req *aliasRequest) (*struct{}, error) {
	if err := req.check(); err != nil {
		return nil, err
	}
	return nil, s.store.UpdateAlias(req.AliasName, req.TargetKeyId)
}

type deleteAliasRequest struct {
	AliasName string `json:"AliasName"`
}

func (s *Server) deleteAlias(req *deleteAliasRequest) (*struct{}, error) {
	if err := requireString("aliasName", req.AliasName, 256); err != nil {
		return nil, err
	}
	return nil, s.store.DeleteAlias(req.AliasName)
}

type aliasListEntry struct {
	AliasArn        string  `json:"AliasArn"`
	AliasName       string  `json:"AliasName"`
	CreationDate    float64 `json:"CreationDate"`
	LastUpdatedDate float64 `json:"LastUpdatedDate"`
	TargetKeyId     string  `json:"TargetKeyId"`
}

type listAliasesResponse struct {
	Aliases    []aliasListEntry `json:"Aliases"`
	NextMarker string           `json:"NextMarker,omitempty"`
	Truncated  bool             `json:"Truncated"`
}

func (s *Server) listAliases(req *listRequest) (*listAliasesResponse, error) {
	limit, err := checkPaging(req.Limit, req.Marker, 100)
	if err != nil {
		return nil, err
	}
	if req.KeyId != "" {
		if err := requireString("keyId", req.KeyId, 2048); err != nil {
			return nil, err
		}
	}
	aliases, next, err := s.store.ListAliases(req.KeyId, limit, req.Marker)
	if err != nil {
		return nil, err
	}
	resp := &listAliasesResponse{Aliases: []aliasListEntry{}, NextMarker: next, Truncated: next != ""}
	for _, a := range aliases {
		resp.Aliases = append(resp.Aliases, aliasListEntry{
			AliasArn: a.ARN, AliasName: a.Name, TargetKeyId: a.TargetKeyID,
			CreationDate: epoch(a.Created), LastUpdatedDate: epoch(a.Updated),
		})
	}
	return resp, nil
}

type tagResourceRequest struct {
	KeyId string `json:"KeyId"`
	Tags  []tag  `json:"Tags"`
}

func (s *Server) tagResource(req *tagResourceRequest) (*struct{}, error) {
	if err := requireString("keyId", req.KeyId, 2048); err != nil {
		return nil, err
	}
	if len(req.Tags) == 0 {
		return nil, validation("1 validation error detected: Value null at 'tags' failed to satisfy constraint: Member must not be null")
	}
	return nil, s.store.TagResource(req.KeyId, toStorageTags(req.Tags))
}

type untagResourceRequest struct {
	KeyId   string   `json:"KeyId"`
	TagKeys []string `json:"TagKeys"`
}

func (s *Server) untagResource(req *untagResourceRequest) (*struct{}, error) {
	if err := requireString("keyId", req.KeyId, 2048); err != nil {
		return nil, err
	}
	if len(req.TagKeys) == 0 {
		return nil, validation("1 validation error detected: Value null at 'tagKeys' failed to satisfy constraint: Member must not be null")
	}
	return nil, s.store.UntagResource(req.KeyId, req.TagKeys)
}

type listResourceTagsResponse struct {
	NextMarker string `json:"NextMarker,omitempty"`
	Tags       []tag  `json:"Tags"`
	Truncated  bool   `json:"Truncated"`
}

func (s *Server) listResourceTags(req *listRequest) (*listResourceTagsResponse, error) {
	if err := requireString("keyId", req.KeyId, 2048); err != nil {
		return nil, err
	}
	limit, err := checkPaging(req.Limit, req.Marker, 1000)
	if err != nil {
		return nil, err
	}
	tags, next, err := s.store.ListResourceTags(req.KeyId, limit, req.Marker)
	if err != nil {
		return nil, err
	}
	resp := &listResourceTagsResponse{Tags: []tag{}, NextMarker: next, Truncated: next != ""}
	for _, t := range tags {
		resp.Tags = append(resp.Tags, tag{TagKey: t.Key, TagValue: t.Value})
	}
	return resp, nil
}
