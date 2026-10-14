package storage

import "crypto"

// KeySpec is the AWS KMS key spec of a KMS key.
type KeySpec string

// Key specs the emulator can create.
const (
	SpecSymmetricDefault KeySpec = "SYMMETRIC_DEFAULT"
	SpecRSA2048          KeySpec = "RSA_2048"
	SpecRSA3072          KeySpec = "RSA_3072"
	SpecRSA4096          KeySpec = "RSA_4096"
	SpecECCNISTP256      KeySpec = "ECC_NIST_P256"
	SpecECCNISTP384      KeySpec = "ECC_NIST_P384"
	SpecECCNISTP521      KeySpec = "ECC_NIST_P521"
	SpecECCSECGP256K1    KeySpec = "ECC_SECG_P256K1"
	SpecEd25519          KeySpec = "ECC_NIST_EDWARDS25519"
)

// knownSpecs are all KeySpec values AWS accepts in CreateKey, including the
// ones this emulator does not implement.
var knownSpecs = map[KeySpec]bool{
	"SYMMETRIC_DEFAULT": true, "RSA_2048": true, "RSA_3072": true, "RSA_4096": true,
	"ECC_NIST_P256": true, "ECC_NIST_P384": true, "ECC_NIST_P521": true,
	"ECC_SECG_P256K1": true, "ECC_NIST_EDWARDS25519": true,
	"HMAC_224": true, "HMAC_256": true, "HMAC_384": true, "HMAC_512": true,
	"SM2": true, "ML_DSA_44": true, "ML_DSA_65": true, "ML_DSA_87": true,
}

// KeyUsage is the KeyUsage of a KMS key.
type KeyUsage string

const (
	UsageSignVerify     KeyUsage = "SIGN_VERIFY"
	UsageEncryptDecrypt KeyUsage = "ENCRYPT_DECRYPT"
)

var knownUsages = map[KeyUsage]bool{
	"SIGN_VERIFY": true, "ENCRYPT_DECRYPT": true,
	"GENERATE_VERIFY_MAC": true, "KEY_AGREEMENT": true,
}

// KeyState is the KeyState of a KMS key, as AWS spells it.
type KeyState string

const (
	StateEnabled         KeyState = "Enabled"
	StateDisabled        KeyState = "Disabled"
	StatePendingDeletion KeyState = "PendingDeletion"
)

// SigningAlgorithm is a Sign/Verify SigningAlgorithm.
type SigningAlgorithm string

const (
	AlgRSAPSSSHA256   SigningAlgorithm = "RSASSA_PSS_SHA_256"
	AlgRSAPSSSHA384   SigningAlgorithm = "RSASSA_PSS_SHA_384"
	AlgRSAPSSSHA512   SigningAlgorithm = "RSASSA_PSS_SHA_512"
	AlgRSAPKCS1SHA256 SigningAlgorithm = "RSASSA_PKCS1_V1_5_SHA_256"
	AlgRSAPKCS1SHA384 SigningAlgorithm = "RSASSA_PKCS1_V1_5_SHA_384"
	AlgRSAPKCS1SHA512 SigningAlgorithm = "RSASSA_PKCS1_V1_5_SHA_512"
	AlgECDSASHA256    SigningAlgorithm = "ECDSA_SHA_256"
	AlgECDSASHA384    SigningAlgorithm = "ECDSA_SHA_384"
	AlgECDSASHA512    SigningAlgorithm = "ECDSA_SHA_512"
	AlgEd25519        SigningAlgorithm = "ED25519_SHA_512"
	AlgEd25519ph      SigningAlgorithm = "ED25519_PH_SHA_512"
)

// knownAlgs are all SigningAlgorithm values AWS accepts, including the ones
// this emulator does not implement (SM2DSA, ML_DSA_SHAKE_256).
var knownAlgs = map[SigningAlgorithm]bool{
	AlgRSAPSSSHA256: true, AlgRSAPSSSHA384: true, AlgRSAPSSSHA512: true,
	AlgRSAPKCS1SHA256: true, AlgRSAPKCS1SHA384: true, AlgRSAPKCS1SHA512: true,
	AlgECDSASHA256: true, AlgECDSASHA384: true, AlgECDSASHA512: true,
	"SM2DSA": true, "ML_DSA_SHAKE_256": true,
	AlgEd25519: true, AlgEd25519ph: true,
}

// IsKnownSigningAlgorithm reports whether alg is a SigningAlgorithm value in
// the AWS API.
func IsKnownSigningAlgorithm(alg string) bool { return knownAlgs[SigningAlgorithm(alg)] }

// MessageType is a Sign/Verify MessageType.
type MessageType string

const (
	MessageRaw        MessageType = "RAW"
	MessageDigest     MessageType = "DIGEST"
	MessageExternalMu MessageType = "EXTERNAL_MU"
)

// IsKnownMessageType reports whether mt is a MessageType value in the AWS API.
func IsKnownMessageType(mt string) bool {
	switch MessageType(mt) {
	case MessageRaw, MessageDigest, MessageExternalMu:
		return true
	}
	return false
}

// signingAlgorithms lists the algorithms per key spec, in the order AWS
// documents them.
var signingAlgorithms = map[KeySpec][]SigningAlgorithm{
	SpecRSA2048:       rsaAlgs,
	SpecRSA3072:       rsaAlgs,
	SpecRSA4096:       rsaAlgs,
	SpecECCNISTP256:   {AlgECDSASHA256},
	SpecECCNISTP384:   {AlgECDSASHA384},
	SpecECCNISTP521:   {AlgECDSASHA512},
	SpecECCSECGP256K1: {AlgECDSASHA256},
	SpecEd25519:       {AlgEd25519, AlgEd25519ph},
}

var rsaAlgs = []SigningAlgorithm{
	AlgRSAPSSSHA256, AlgRSAPSSSHA384, AlgRSAPSSSHA512,
	AlgRSAPKCS1SHA256, AlgRSAPKCS1SHA384, AlgRSAPKCS1SHA512,
}

func supportsAlgorithm(spec KeySpec, alg SigningAlgorithm) bool {
	for _, a := range signingAlgorithms[spec] {
		if a == alg {
			return true
		}
	}
	return false
}

// algHash is the hash a signing algorithm applies to the message. For
// ED25519_PH_SHA_512 it is the SHA-512 AWS requires the caller's digest to
// have the length of.
func algHash(alg SigningAlgorithm) crypto.Hash {
	switch alg {
	case AlgRSAPSSSHA256, AlgRSAPKCS1SHA256, AlgECDSASHA256:
		return crypto.SHA256
	case AlgRSAPSSSHA384, AlgRSAPKCS1SHA384, AlgECDSASHA384:
		return crypto.SHA384
	case AlgRSAPSSSHA512, AlgRSAPKCS1SHA512, AlgECDSASHA512, AlgEd25519, AlgEd25519ph:
		return crypto.SHA512
	}
	return 0
}
