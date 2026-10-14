// Package server speaks the AWS JSON 1.1 protocol that the AWS KMS API uses:
// every call is a POST to "/" with the operation in the X-Amz-Target header
// ("TrentService.<Operation>") and a JSON body. Each operation decodes its
// request, calls the storage package, and encodes the response or the error.
package server

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/blackwell-systems/aws-kms-emulator/internal/storage"
)

const (
	contentType  = "application/x-amz-json-1.1"
	targetPrefix = "TrentService."
	maxBodyBytes = 256 << 10
)

// Options configure a Server.
type Options struct {
	// StrictAuth makes the server reject requests without a well-formed SigV4
	// Authorization header. Signatures are never validated.
	StrictAuth bool
	// Logf, when set, receives one line per request.
	Logf func(format string, args ...any)
}

// Server is an http.Handler implementing the KMS API.
type Server struct {
	store *storage.Store
	opts  Options
	ops   map[string]operation
}

type operation func(body []byte) (any, error)

// New returns a Server backed by store.
func New(store *storage.Store, opts Options) *Server {
	s := &Server{store: store, opts: opts}
	s.ops = map[string]operation{
		"CreateKey":           op(s.createKey),
		"DescribeKey":         op(s.describeKey),
		"GetPublicKey":        op(s.getPublicKey),
		"Sign":                op(s.sign),
		"Verify":              op(s.verify),
		"ListKeys":            op(s.listKeys),
		"EnableKey":           op(s.enableKey),
		"DisableKey":          op(s.disableKey),
		"ScheduleKeyDeletion": op(s.scheduleKeyDeletion),
		"CancelKeyDeletion":   op(s.cancelKeyDeletion),
		"CreateAlias":         op(s.createAlias),
		"UpdateAlias":         op(s.updateAlias),
		"DeleteAlias":         op(s.deleteAlias),
		"ListAliases":         op(s.listAliases),
		"TagResource":         op(s.tagResource),
		"UntagResource":       op(s.untagResource),
		"ListResourceTags":    op(s.listResourceTags),
	}
	return s
}

// knownOperations are KMS API operations that exist in AWS but that this
// emulator does not implement. They get a distinct error, so a missing
// operation is not mistaken for a typo.
var knownOperations = map[string]bool{
	"ConnectCustomKeyStore": true, "CreateCustomKeyStore": true, "CreateGrant": true,
	"Decrypt": true, "DeleteCustomKeyStore": true, "DeleteImportedKeyMaterial": true,
	"DeriveSharedSecret": true, "DescribeCustomKeyStores": true, "DisableKeyRotation": true,
	"DisconnectCustomKeyStore": true, "EnableKeyRotation": true, "Encrypt": true,
	"GenerateDataKey": true, "GenerateDataKeyPair": true, "GenerateDataKeyPairWithoutPlaintext": true,
	"GenerateDataKeyWithoutPlaintext": true, "GenerateMac": true, "GenerateRandom": true,
	"GetKeyPolicy": true, "GetKeyRotationStatus": true, "GetParametersForImport": true,
	"ImportKeyMaterial": true, "ListGrants": true, "ListKeyPolicies": true,
	"ListKeyRotations": true, "ListRetirableGrants": true, "PutKeyPolicy": true,
	"ReEncrypt": true, "ReplicateKey": true, "RetireGrant": true, "RevokeGrant": true,
	"RotateKeyOnDemand": true, "UpdateCustomKeyStore": true, "UpdateKeyDescription": true,
	"UpdatePrimaryRegion": true, "VerifyMac": true,
}

// op adapts a typed handler to the generic operation signature: it decodes the
// JSON request body into Req and encodes the *Resp the handler returns.
func op[Req, Resp any](fn func(*Req) (*Resp, error)) operation {
	return func(body []byte) (any, error) {
		var req Req
		if len(strings.TrimSpace(string(body))) > 0 {
			if err := json.Unmarshal(body, &req); err != nil {
				return nil, &apiError{status: http.StatusBadRequest, code: "SerializationException", message: "Start of structure or map found where not expected."}
			}
		}
		resp, err := fn(&req)
		if err != nil || resp == nil {
			return nil, err
		}
		return resp, nil
	}
}

// apiError is an error with an explicit HTTP status, for failures that do not
// come from the storage package.
type apiError struct {
	status  int
	code    string
	message string
}

func (e *apiError) Error() string { return e.code + ": " + e.message }

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqID := newRequestID()
	w.Header().Set("x-amzn-RequestId", reqID)

	if r.Method == http.MethodGet && r.URL.Path == "/health" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/" {
		s.writeError(w, &apiError{status: http.StatusNotFound, code: "UnknownOperationException", message: "KMS API calls are POST requests to /."})
		return
	}
	if s.opts.StrictAuth {
		if err := checkAuthorization(r); err != nil {
			s.writeError(w, err)
			return
		}
	}
	target := r.Header.Get("X-Amz-Target")
	name, ok := strings.CutPrefix(target, targetPrefix)
	if !ok || name == "" {
		s.writeError(w, &apiError{status: http.StatusNotFound, code: "UnknownOperationException", message: "Missing or malformed X-Amz-Target header; expected TrentService.<Operation>."})
		return
	}
	handler, ok := s.ops[name]
	if !ok {
		if knownOperations[name] {
			s.writeError(w, &apiError{status: http.StatusNotImplemented, code: "NotImplementedException", message: name + " is a KMS operation that aws-kms-emulator does not implement."})
			return
		}
		s.writeError(w, &apiError{status: http.StatusNotFound, code: "UnknownOperationException", message: name + " is not a KMS operation."})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			s.writeError(w, &apiError{status: http.StatusRequestEntityTooLarge, code: "RequestEntityTooLargeException", message: "The request entity is too large."})
			return
		}
		s.writeError(w, &apiError{status: http.StatusBadRequest, code: "RequestAbortedException", message: "The request body could not be read."})
		return
	}
	resp, err := handler(body)
	if s.opts.Logf != nil {
		if err != nil {
			s.opts.Logf("%s -> %v", name, err)
		} else {
			s.opts.Logf("%s -> ok", name)
		}
	}
	if err != nil {
		s.writeError(w, err)
		return
	}
	s.writeJSON(w, resp)
}

func (s *Server) writeJSON(w http.ResponseWriter, resp any) {
	w.Header().Set("Content-Type", contentType)
	if resp == nil {
		return
	}
	data, err := json.Marshal(resp)
	if err != nil {
		s.writeError(w, &storage.Error{Code: storage.CodeInternal, Message: "encoding the response failed"})
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) writeError(w http.ResponseWriter, err error) {
	status, code, message := http.StatusInternalServerError, storage.CodeInternal, err.Error()
	var se *storage.Error
	var ae *apiError
	switch {
	case errors.As(err, &se):
		status, code, message = http.StatusBadRequest, se.Code, se.Message
		if se.Code == storage.CodeInternal {
			status = http.StatusInternalServerError
		}
	case errors.As(err, &ae):
		status, code, message = ae.status, ae.code, ae.message
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("x-amzn-ErrorType", code)
	w.WriteHeader(status)
	data, _ := json.Marshal(map[string]string{"__type": code, "message": message})
	_, _ = w.Write(data)
}

// checkAuthorization enforces the strict mode: the request must carry an
// Authorization header shaped like a SigV4 one for the kms service. The
// signature itself is never checked.
func checkAuthorization(r *http.Request) *apiError {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return &apiError{status: http.StatusForbidden, code: "MissingAuthenticationToken", message: "Missing Authentication Token"}
	}
	rest, ok := strings.CutPrefix(auth, "AWS4-HMAC-SHA256 ")
	if !ok {
		return &apiError{status: http.StatusForbidden, code: "IncompleteSignature", message: "Authorization header requires an AWS4-HMAC-SHA256 signature."}
	}
	fields := map[string]string{}
	for _, part := range strings.Split(rest, ",") {
		k, v, found := strings.Cut(strings.TrimSpace(part), "=")
		if found {
			fields[k] = v
		}
	}
	for _, name := range []string{"Credential", "SignedHeaders", "Signature"} {
		if fields[name] == "" {
			return &apiError{status: http.StatusForbidden, code: "IncompleteSignature", message: fmt.Sprintf("Authorization header requires '%s' parameter.", name)}
		}
	}
	// Credential=<access key>/<date>/<region>/<service>/aws4_request
	scope := strings.Split(fields["Credential"], "/")
	if len(scope) != 5 || scope[0] == "" || scope[3] != "kms" || scope[4] != "aws4_request" {
		return &apiError{status: http.StatusForbidden, code: "IncompleteSignature", message: "Credential should be scoped to the kms service: <access key>/<date>/<region>/kms/aws4_request."}
	}
	if r.Header.Get("X-Amz-Date") == "" && r.Header.Get("Date") == "" {
		return &apiError{status: http.StatusForbidden, code: "IncompleteSignature", message: "Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header."}
	}
	return nil
}

func newRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
