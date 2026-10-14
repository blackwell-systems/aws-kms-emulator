# Features

What the AWS KMS emulator supports, and what it does not. For how each behaviour was derived from AWS's documentation, see [AWS-BEHAVIOUR.md](AWS-BEHAVIOUR.md).

## Protocol

- AWS JSON 1.1 over HTTP: `POST /` with `X-Amz-Target: TrentService.<Operation>`
- Reached by `aws-sdk-go-v2`, the other official SDKs and the AWS CLI through a custom endpoint
- SigV4 requests are accepted and never validated. Optional strict mode requires a well-formed `Authorization` header for the `kms` service
- Blobs are base64 in JSON, timestamps are epoch seconds, errors carry `x-amzn-ErrorType` and `__type`
- `GET /health` returns 200
- Request bodies are limited to 256 KiB (`RequestEntityTooLargeException`)

## Operations

### Keys
- **CreateKey**: `SIGN_VERIFY` keys of every spec below; `Description`; `Tags`; `KeySpec` or the deprecated `CustomerMasterKeySpec`. `Policy` is accepted and ignored
- **DescribeKey**: by key ID, key ARN, alias name or alias ARN. Reports `KeyState`, `Enabled`, `SigningAlgorithms`, and `DeletionDate` and `PendingDeletionWindowInDays` for a key pending deletion
- **GetPublicKey**: DER SubjectPublicKeyInfo for every spec, including secp256k1 and Ed25519
- **ListKeys**: ordered by key ID, paginated with `Limit` (1 to 1000) and `Marker`
- **EnableKey**, **DisableKey**: idempotent; rejected on a key pending deletion
- **ScheduleKeyDeletion**: `PendingWindowInDays` 7 to 30, default 30
- **CancelKeyDeletion**: the key returns as `Disabled`

### Signing
- **Sign**, **Verify**: `MessageType` `RAW` (default) or `DIGEST`. Messages are 1 to 4096 bytes. ECDSA signatures are DER, Ed25519 and RSA signatures are raw. An invalid signature is `KMSInvalidSignatureException`

| Key spec | Signing algorithms |
|----------|--------------------|
| `ECC_NIST_P256` | `ECDSA_SHA_256` |
| `ECC_NIST_P384` | `ECDSA_SHA_384` |
| `ECC_NIST_P521` | `ECDSA_SHA_512` |
| `ECC_SECG_P256K1` | `ECDSA_SHA_256` |
| `ECC_NIST_EDWARDS25519` | `ED25519_SHA_512` (RAW only), `ED25519_PH_SHA_512` (DIGEST only) |
| `RSA_2048`, `RSA_3072`, `RSA_4096` | `RSASSA_PSS_SHA_256/384/512`, `RSASSA_PKCS1_V1_5_SHA_256/384/512` |

### Aliases
- **CreateAlias**, **UpdateAlias**, **DeleteAlias**, **ListAliases**: name rules, the reserved `alias/aws/` prefix, 50 aliases per key, `ListAliases` paginated (`Limit` 1 to 100) with an optional `KeyId` filter
- An alias works wherever AWS accepts one as `KeyId`: `DescribeKey`, `GetPublicKey`, `Sign`, `Verify`. Lifecycle and tagging operations take a key ID or key ARN only, as documented

### Tags
- **TagResource**, **UntagResource**, **ListResourceTags**: 50 tags per key, `aws:` prefix reserved, paginated

### Symmetric keys
`CreateKey` without a `KeySpec` makes a `SYMMETRIC_DEFAULT` key with `ENCRYPT_DECRYPT` usage. It has no key material: `Sign` and `Verify` reject it with `InvalidKeyUsageException`, `GetPublicKey` with `UnsupportedOperationException`, and `Encrypt` and `Decrypt` return `NotImplementedException`. It exists so tests can check key-usage handling.

## Errors

`ValidationException`, `NotFoundException`, `DisabledException`, `KMSInvalidStateException`, `InvalidKeyUsageException`, `KMSInvalidSignatureException`, `InvalidArnException`, `AlreadyExistsException`, `InvalidAliasNameException`, `LimitExceededException`, `TagException`, `InvalidMarkerException`, `UnsupportedOperationException`, `KMSInternalException`, and for the protocol layer `SerializationException`, `UnknownOperationException`, `RequestEntityTooLargeException`, `MissingAuthenticationToken`, `IncompleteSignature`.

## Persistence

`AWS_KMS_DATA_DIR` (or `WithDataDir`) keeps keys, aliases, tags and states in `state.json`, rewritten atomically after every change. Private keys are stored in plaintext with mode `0600`: development keys only. See the README for details.

## Library API

- `awskmsemulator.New(opts...)`: an `http.Handler` with its own state
- `awskmsemulator.Register(mux, opts...)`: mounts the handler on a `ServeMux`
- `awskmsemulator.FromEnv()`: the options the `AWS_KMS_*` variables ask for
- Options: `WithDataDir`, `WithRegion`, `WithAccountID`, `WithStrictAuth`, `WithClock`, `WithLogf`
- `kmstest.NewServer(tb, opts...)`: starts an `httptest` server, closed when the test ends; `.Client()` and `.Config()` give an `aws-sdk-go-v2` client and config for it

## Not supported

| Area | Status |
|------|--------|
| `Encrypt`, `Decrypt`, `ReEncrypt`, `GenerateDataKey*`, `GenerateRandom` | `NotImplementedException` |
| `GenerateMac`, `VerifyMac`, `DeriveSharedSecret` | `NotImplementedException`; `CreateKey` for HMAC and `KEY_AGREEMENT` keys returns `UnsupportedOperationException` |
| RSA `ENCRYPT_DECRYPT` keys | `UnsupportedOperationException` at `CreateKey` |
| Key policies, grants, IAM | Not modelled; nothing is authorized or denied. `GetKeyPolicy`, `PutKeyPolicy`, grants: `NotImplementedException` |
| Key rotation, imported key material, `ReplicateKey`, multi-Region keys, custom key stores | `NotImplementedException` / `UnsupportedOperationException` |
| `UpdateKeyDescription` | `NotImplementedException` |
| `SM2`, `ML_DSA_*` keys, `EXTERNAL_MU` | `UnsupportedOperationException` |
| AWS-managed keys and aliases | None exist |
| Several accounts or Regions | One of each per emulator (`WithRegion`, `WithAccountID`). A request signed for another Region is served all the same; an ARN naming another Region or account is `NotFoundException` |
| `DryRun` | Accepted and ignored (AWS answers `DryRunOperationException`) |
| Rate limits, eventual consistency | None |
