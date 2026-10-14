package storage

import "fmt"

// Error codes. They are the exception names AWS KMS returns in the
// X-Amzn-ErrorType header and the __type field of the JSON error body.
const (
	CodeValidation           = "ValidationException"
	CodeNotFound             = "NotFoundException"
	CodeDisabled             = "DisabledException"
	CodeInvalidState         = "KMSInvalidStateException"
	CodeInvalidKeyUsage      = "InvalidKeyUsageException"
	CodeInvalidArn           = "InvalidArnException"
	CodeInvalidSignature     = "KMSInvalidSignatureException"
	CodeAlreadyExists        = "AlreadyExistsException"
	CodeInvalidAliasName     = "InvalidAliasNameException"
	CodeLimitExceeded        = "LimitExceededException"
	CodeTag                  = "TagException"
	CodeInvalidMarker        = "InvalidMarkerException"
	CodeUnsupportedOperation = "UnsupportedOperationException"
	CodeInternal             = "KMSInternalException"
)

// Error is a KMS API error. The server turns it into an AWS JSON 1.1 error
// response.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func newErr(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}
