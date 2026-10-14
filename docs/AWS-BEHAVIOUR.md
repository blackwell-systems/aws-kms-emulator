# AWS behaviour the emulator follows

Every rule here was read from AWS's own documentation on 2026-10-14. The tests in `conformance_test.go`, `validation_test.go` and the other `*_test.go` files in the repository root encode them. Each section lists the page that settles it, and each table ends with what the documentation does **not** settle, so you know where the emulator makes a judgment call.

The emulator has not been compared against the live service. A rule marked "documented" comes from the pages below; a rule marked "inferred" is the emulator's reading of them or of known AWS behaviour, and could differ from AWS in an edge case.

## Sources

| Short name | Page |
|------------|------|
| Sign | https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html |
| Verify | https://docs.aws.amazon.com/kms/latest/APIReference/API_Verify.html |
| GetPublicKey | https://docs.aws.amazon.com/kms/latest/APIReference/API_GetPublicKey.html |
| CreateKey | https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html |
| DescribeKey | https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html |
| ListKeys | https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeys.html |
| ScheduleKeyDeletion | https://docs.aws.amazon.com/kms/latest/APIReference/API_ScheduleKeyDeletion.html |
| CancelKeyDeletion | https://docs.aws.amazon.com/kms/latest/APIReference/API_CancelKeyDeletion.html |
| EnableKey | https://docs.aws.amazon.com/kms/latest/APIReference/API_EnableKey.html |
| CreateAlias | https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateAlias.html |
| ListAliases | https://docs.aws.amazon.com/kms/latest/APIReference/API_ListAliases.html |
| TagResource | https://docs.aws.amazon.com/kms/latest/APIReference/API_TagResource.html |
| ListResourceTags | https://docs.aws.amazon.com/kms/latest/APIReference/API_ListResourceTags.html |
| Tag | https://docs.aws.amazon.com/kms/latest/APIReference/API_Tag.html |
| Common errors | https://docs.aws.amazon.com/kms/latest/APIReference/CommonErrors.html |
| Key spec reference | https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html |
| Key states | https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html |
| Quotas | https://docs.aws.amazon.com/kms/latest/developerguide/resource-limits.html |

## Protocol

KMS uses the AWS JSON 1.1 protocol: `POST /` with `Content-Type: application/x-amz-json-1.1`, the operation in `X-Amz-Target: TrentService.<Operation>`, and a JSON body (the example requests on every API page above). Blobs (`Message`, `Signature`, `PublicKey`) are base64 strings in JSON (Sign, "When you use the HTTP API or the AWS CLI, the value is Base64-encoded"). Timestamps are JSON numbers of epoch seconds (the ListAliases and ScheduleKeyDeletion examples). Errors are HTTP 400 unless the page says 500, with the exception name in `x-amzn-ErrorType` and `__type`, and the text in `message`.

Common errors (Common errors page): `UnknownOperationException` is HTTP 404, `IncompleteSignature` is 403, `RequestEntityTooLargeException` is 413. `MissingAuthenticationToken` (403) is not on that page; the emulator uses it for an absent `Authorization` header in strict mode, as AWS does (inferred).

## Sign and Verify

| Rule | Source | Status |
|------|--------|--------|
| `KeyId` is 1 to 2048 characters; key ID, key ARN, alias name or alias ARN | Sign | documented |
| `Message` is 1 to 4096 bytes, for RAW and DIGEST alike | Sign: "Length Constraints: Minimum length of 1. Maximum length of 4096" | documented |
| `Signature` (Verify) is 1 to 6144 bytes | Verify | documented |
| `MessageType` is `RAW`, `DIGEST` or `EXTERNAL_MU`; omitted means RAW | Sign | documented |
| A DIGEST must be exactly as long as the hash of the algorithm | Sign: "the length of the Message value must match the length of hashed messages for the specified signing algorithm" | documented |
| `ED25519_SHA_512` requires RAW; `ED25519_PH_SHA_512` requires DIGEST | Sign, Key spec reference | documented |
| `ED25519_PH_SHA_512` with DIGEST hashes the digest again with SHA-512 (Ed25519ph over SHA-512 of your 64-byte digest) | Sign: "the input is hashed twice: once by you and once by KMS" | documented |
| ECDSA signatures are DER (X9.62, RFC 3279), Ed25519 and RSA signatures are the raw bytes | Sign | documented |
| `ECDSA_SHA_256` for P-256 and secp256k1, `_384` for P-384, `_512` for P-521, `ED25519_*` for Edwards25519, the six RSA algorithms for RSA keys | Key spec reference | documented |
| RSA-PSS uses a salt as long as the hash, and MGF1 with the same hash | Key spec reference | documented |
| An algorithm that the key spec does not support is `InvalidKeyUsageException` | Sign, errors: "The encryption algorithm or signing algorithm specified for the operation is incompatible with the type of key material" | documented |
| A key whose `KeyUsage` is not `SIGN_VERIFY` is `InvalidKeyUsageException` | Sign, errors | documented |
| A signature that does not verify is `KMSInvalidSignatureException`, not `SignatureValid: false` | Verify: "the Verify operation fails with an KMSInvalidSignatureException exception" | documented |
| Verify does not need the same `MessageType` as Sign; a message and its digest are the same message | Verify | documented |
| Disabled key: `DisabledException` | Key states, footnote [1] | documented |
| Unknown key or alias: `NotFoundException` | Sign, errors | documented |
| Malformed ARN: `InvalidArnException` | DescribeKey, errors | documented (the condition is "not valid") |
| The response `KeyId` is the key ARN, also when the request used an alias | Sign: "The Amazon Resource Name (key ARN) of the asymmetric KMS key" | documented |

Not settled by the documentation, so inferred:

- The exception for a `MessageType` that an algorithm forbids (`ED25519_SHA_512` with DIGEST and the like) and for a DIGEST of the wrong length. The emulator returns `ValidationException`.
- The exception for a key that is pending deletion. The key-state table lists, for Sign, Verify and GetPublicKey, "[2] or [3]": `DisabledException` or `KMSInvalidStateException`. The emulator returns `DisabledException`, with the message "... is pending deletion.".
- The exact text of every error message. Codes and HTTP statuses follow the documentation; messages are written to be useful, and AWS's wording differs in places. Match on the code, not the message.
- `EXTERNAL_MU` is documented for ML-DSA only. The emulator rejects it with `ValidationException`.
- Check order: field shape first (`ValidationException`), then key lookup, key state, key usage, algorithm against key spec, and last the message type and length rules. AWS does not document the order.
- Signatures from `ECC_SECG_P256K1` are always low-S in the emulator. AWS does not document that it normalizes S, and verifiers that accept AWS signatures accept both forms.

## Keys

| Rule | Source | Status |
|------|--------|--------|
| `KeySpec` defaults to `SYMMETRIC_DEFAULT`, `KeyUsage` to `ENCRYPT_DECRYPT` | CreateKey | documented |
| `KeyUsage` is required for every key but a symmetric encryption key | CreateKey: "This parameter is optional when you are creating a symmetric encryption KMS key; otherwise, it is required" | documented |
| Valid usage by spec: RSA: `ENCRYPT_DECRYPT` or `SIGN_VERIFY`; NIST ECC: `SIGN_VERIFY` or `KEY_AGREEMENT`; secp256k1: `SIGN_VERIFY`; Ed25519: `SIGN_VERIFY` only; HMAC: `GENERATE_VERIFY_MAC` | CreateKey, Key spec reference | documented |
| `Description` is at most 8192 characters | CreateKey | documented |
| `KeySpec` and the deprecated `CustomerMasterKeySpec` are the same parameter; responses carry both | CreateKey, Key spec reference | documented |
| The key ID is a UUID; the ARN is `arn:aws:kms:<region>:<account>:key/<id>` | CreateKey example | documented |
| `KeyManager` is `CUSTOMER`, `Origin` is `AWS_KMS`, `MultiRegion` is false | CreateKey example | documented |
| `SigningAlgorithms` appears only for `SIGN_VERIFY` keys; `EncryptionAlgorithms` only for `ENCRYPT_DECRYPT` keys | GetPublicKey, CreateKey | documented |
| `GetPublicKey` returns a DER X.509 SubjectPublicKeyInfo, `KeySpec`, `KeyUsage` and `SigningAlgorithms` | GetPublicKey | documented |
| Key states are `Enabled`, `Disabled`, `PendingDeletion`; `Enabled` is true only for `Enabled` | Key states, DescribeKey | documented |
| `ListKeys` lists keys in every state; `Limit` is 1 to 1000, default 100 | ListKeys, Quotas | documented |
| 50 tags per key; tag key 1 to 128 characters, value 0 to 256 | Tag, TagResource, Quotas | the tag count limit is the general AWS limit (inferred for KMS) |
| Tags beginning `aws:` are reserved (`TagException`) | TagResource: `TagException` "one or more tags are not valid" | inferred, from AWS's general tagging rules |

Not settled: which exception a KeySpec and KeyUsage combination that AWS forbids produces (`ValidationException` in the emulator); the exact reaction to `CreateKey` with a `Policy` (the emulator accepts and ignores policies, and rejects only one over 32768 characters with `LimitExceededException`).

## Lifecycle

| Rule | Source | Status |
|------|--------|--------|
| `ScheduleKeyDeletion`: `PendingWindowInDays` 7 to 30, default 30; the response has `KeyId` (ARN), `KeyState`, `DeletionDate`, `PendingWindowInDays` | ScheduleKeyDeletion | documented |
| After the window, the key and its aliases are deleted | ScheduleKeyDeletion: "all aliases that refer to it" | documented |
| `CancelKeyDeletion` leaves the key `Disabled`, and returns the key ARN | CancelKeyDeletion | documented |
| `CancelKeyDeletion` on a key that is not pending: `KMSInvalidStateException` "is not pending deletion" | Key states, footnote [4] | documented |
| Operations on a pending key: Sign, Verify, GetPublicKey fail; DescribeKey, ListResourceTags, DeleteAlias succeed; EnableKey, DisableKey, ScheduleKeyDeletion, TagResource, CreateAlias fail with `KMSInvalidStateException` | Key states table | documented |
| On a disabled key: Sign and Verify fail with `DisabledException`; GetPublicKey, DescribeKey, EnableKey, DisableKey, ScheduleKeyDeletion, TagResource, CreateAlias succeed | Key states table | documented |
| EnableKey on an enabled key, and DisableKey on a disabled key, succeed | Key states table (no failure marked) | documented |
| `UpdateAlias`: succeeds if the source key is pending deletion, fails with `KMSInvalidStateException` if the destination is | Key states, footnote [10] | documented |

`conformance_test.go` runs the whole key-state table: every operation above against a key in each state.

## Aliases

| Rule | Source | Status |
|------|--------|--------|
| Name matches `^alias/[a-zA-Z0-9/_-]+$`, 1 to 256 characters; `alias/aws/` is reserved | CreateAlias | documented |
| `TargetKeyId` is a key ID or key ARN (not an alias) | CreateAlias | documented |
| Duplicate name: `AlreadyExistsException`; bad name: `InvalidAliasNameException`; quota: `LimitExceededException` | CreateAlias, errors | documented |
| 50 aliases per key | Quotas | documented |
| `ListAliases`: `Limit` 1 to 100, default 50; optional `KeyId` filter; entries carry `AliasArn`, `AliasName`, `TargetKeyId`, `CreationDate`, `LastUpdatedDate` | ListAliases | documented |
| A bad `Marker`: `InvalidMarkerException` | ListKeys, ListAliases, ListResourceTags | documented |

Not settled: which of `InvalidAliasNameException` and `ValidationException` a name that breaks the pattern produces. The emulator uses `ValidationException` for a name over 256 characters or empty, and `InvalidAliasNameException` for the rest. AWS-managed aliases (`alias/aws/...`) do not exist in the emulator, so `ListAliases` returns only aliases you create.

## Not modelled

The emulator is one account in one Region. It does not check IAM, key policies or grants (it stores no policy), it does not rate limit, and it has no eventual-consistency delay. `DryRun` is accepted and ignored. See [FEATURES.md](FEATURES.md).
