# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - Unreleased

First version: the KMS signing API, over the AWS JSON 1.1 protocol.

### Added

- AWS JSON 1.1 server (`X-Amz-Target: TrentService.<Operation>`) reachable by `aws-sdk-go-v2`, the other AWS SDKs and the AWS CLI through a custom endpoint
  - SigV4 signatures are accepted and not validated; `AWS_KMS_STRICT_AUTH` / `WithStrictAuth` requires a well-formed `Authorization` header for the `kms` service
- Operations: `CreateKey`, `DescribeKey`, `GetPublicKey`, `Sign`, `Verify`, `ListKeys`, `EnableKey`, `DisableKey`, `ScheduleKeyDeletion`, `CancelKeyDeletion`, `CreateAlias`, `UpdateAlias`, `DeleteAlias`, `ListAliases`, `TagResource`, `UntagResource`, `ListResourceTags`
- Signing with real key material
  - `ECC_NIST_EDWARDS25519`: `ED25519_SHA_512` (RAW) and `ED25519_PH_SHA_512` (DIGEST)
  - `ECC_NIST_P256`, `ECC_NIST_P384`, `ECC_NIST_P521`, `ECC_SECG_P256K1`: ECDSA over RAW messages and DIGESTs, DER signatures
  - `RSA_2048`, `RSA_3072`, `RSA_4096`: RSASSA-PSS and RSASSA-PKCS1-v1_5 with SHA-256, SHA-384, SHA-512
  - `GetPublicKey` returns a DER SubjectPublicKeyInfo for every spec
- AWS's validation and errors: the 4096-byte message limit, digest length rules, the Ed25519 message-type rules, the key-state table (`DisabledException`, `KMSInvalidStateException`), `InvalidKeyUsageException`, `KMSInvalidSignatureException`, alias and tag rules, pagination markers
- Key IDs, key ARNs, alias names and alias ARNs are accepted where AWS accepts them
- Keys scheduled for deletion are removed, with their aliases, when the window passes
- Library: `awskmsemulator.New`, `Register`, `FromEnv` and options; `kmstest.NewServer` starts an in-process server and builds an `aws-sdk-go-v2` client
- Standalone binary `cmd/server` (`AWS_KMS_PORT`, `AWS_KMS_LOG_LEVEL`, `AWS_KMS_REGION`, `AWS_KMS_ACCOUNT_ID`)
- Optional on-disk persistence: set `AWS_KMS_DATA_DIR` and the emulator restores its state from `state.json` on startup and rewrites it after every change. The file holds plaintext private keys with mode `0600` and is meant for development keys only
- Dockerfile (not published)
- `crosscheck/` runs one set of SDK scenarios against any KMS endpoint (build tag `crosscheck`); `docs/AWS-BEHAVIOUR.md` records the comparison with Floci 2.2.0
- docs: `docs/AWS-BEHAVIOUR.md` cites the AWS page behind each behaviour and lists what the documentation does not settle; `docs/FEATURES.md` lists supported and unsupported operations
