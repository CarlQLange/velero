# Design for BSL Client-Side Encryption Support

## Abstract

This design adds client-side encryption of backup data stored in object storage,
using the `age` encryption format with X25519 asymmetric keys. When encryption is
configured on a BackupStorageLocation, Velero encrypts all objects before upload
using a public key and decrypts them after download using the corresponding
private key.

The asymmetric design allows two operational modes:

- **High-security mode**: only the public key is in the cluster. Velero can
  create encrypted backups but cannot restore from them without the private key
  being explicitly provided. A cluster compromise does not expose existing backups.
- **Convenience mode**: both keys are in the cluster. Backups and restores work
  transparently. S3 compromise alone still cannot expose backups.

In both modes, the private key must also be stored outside the cluster (in any
secure external store of the operator's choosing) to enable disaster recovery.

## Background

Velero backups contain sensitive data. The backup tarball includes all Kubernetes
resources in the target namespaces, including Secrets with credentials, TLS keys,
and other sensitive material. These are stored unencrypted in object storage.

Server-side encryption (SSE) does not protect against a compromised storage
credential: an attacker with a valid S3 access key can read the bucket directly,
and the decryption is transparent.

Issue [#434](https://github.com/vmware-tanzu/velero/issues/434) has tracked this
feature request since 2017 and is currently in the Icebox with no upstream
implementation planned.

## Goals

- Encrypt all objects written to object storage before upload
- Decrypt objects transparently on read when the private key is available
- Use a standard encryption format (`age`) so that backups can be decrypted
  outside of Velero using widely available tooling
- Support asymmetric key separation (encrypt-only in cluster, decrypt externally)
- Maintain backward compatibility with existing unencrypted backups
- Require no changes to object storage plugins

## Non-Goals

- Kopia / node-agent volume backup encryption (Kopia has its own encryption)
- Key rotation without re-encrypting existing backups
- Encrypting only a subset of stored objects
- Supporting `velero backup download` against an encrypted store (signed URLs
  bypass Velero's read path; downloaded data will be ciphertext — but it can be
  decrypted locally with the standard `age` CLI)

## High-Level Design

### Why `age`

[`age`](https://age-encryption.org/) is a file encryption format and Go library
(`filippo.io/age`) by Filippo Valsorda (Go security team). Key properties:

- **Standard format**: encrypted files can be decrypted by the `age` CLI on any
  platform, which is critical for disaster recovery
- **Asymmetric X25519**: public key encrypts, private key decrypts, enabling
  key separation between backup and restore paths
- **Streaming**: handles arbitrarily large files without buffering
- **Multiple recipients**: a single encrypted object can be decrypted by any of
  several private keys, enabling separate operational and DR keys
- **Well-audited**: the format and Go implementation have been independently
  audited

Trade-offs:
- Uses ChaCha20-Poly1305 internally (not FIPS-approved; AES-256-GCM is)
- Adds a dependency on `filippo.io/age`

### API Changes

Two new fields are added to `ObjectStorageLocation`:

```go
type ObjectStorageLocation struct {
    Bucket    string `json:"bucket"`
    Prefix    string `json:"prefix,omitempty"`
    CACert    []byte `json:"caCert,omitempty"`
    CACertRef *corev1api.SecretKeySelector `json:"caCertRef,omitempty"`

    // EncryptionPublicKeyRef is a reference to a Secret containing an age
    // X25519 public key (age1...). When set, all objects written to object
    // storage are encrypted before upload.
    // +optional
    EncryptionPublicKeyRef *corev1api.SecretKeySelector `json:"encryptionPublicKeyRef,omitempty"`

    // EncryptionPrivateKeyRef is a reference to a Secret containing an age
    // X25519 private key (AGE-SECRET-KEY-1...). When set, encrypted objects
    // are decrypted on read, enabling restores. If not set but
    // EncryptionPublicKeyRef is set, restore operations will fail with a
    // clear error directing the operator to provide the private key.
    // +optional
    EncryptionPrivateKeyRef *corev1api.SecretKeySelector `json:"encryptionPrivateKeyRef,omitempty"`
}
```

Validation rules:
- `EncryptionPrivateKeyRef` without `EncryptionPublicKeyRef` is invalid
- `EncryptionPublicKeyRef` without `EncryptionPrivateKeyRef` is valid (encrypt-only)
- Both set is valid (full encrypt + decrypt)

### Operational Modes

#### High-Security Mode (encrypt-only)

```yaml
objectStorage:
  bucket: my-velero-backups
  encryptionPublicKeyRef:
    name: velero-encryption-public
    key: key
```

- Backups are encrypted. Restores fail with:
  `"encrypted backup detected but no decryption key (encryptionPrivateKeyRef) is configured"`
- The BSL controller logs a warning during reconciliation:
  `"BSL has encryption enabled but no private key configured — restores will require manual key injection"`
- To restore, three options (in order of convenience):
  1. **CLI flag**: `velero restore create --from-backup my-backup --encryption-private-key private-key.txt`
     (creates a temporary Secret automatically, cleaned up via owner reference)
  2. **Restore CRD**: create a Secret with the private key, then set
     `encryptionPrivateKeyRef` on the Restore spec:
     ```yaml
     apiVersion: velero.io/v1
     kind: Restore
     spec:
       backupName: my-backup
       encryptionPrivateKeyRef:
         name: my-restore-key
         key: key
     ```
  3. **Patch the BSL**: temporarily add `encryptionPrivateKeyRef` to the BSL,
     restore, then remove it

#### Convenience Mode (encrypt + decrypt)

```yaml
objectStorage:
  bucket: my-velero-backups
  encryptionPublicKeyRef:
    name: velero-encryption-public
    key: key
  encryptionPrivateKeyRef:
    name: velero-encryption-private
    key: key
```

- Backups and restores work transparently.
- S3 compromise alone cannot read backups (no key).
- Cluster compromise exposes the private key (trade-off accepted by operator).

### Restore-Time Decryption Key Override

In high-security mode, the BSL has no private key configured. To restore, the
operator must provide the private key. Rather than patching the BSL, a field on
the Restore CRD and a CLI flag allow the key to be provided per-restore.

#### Restore CRD

```go
type RestoreSpec struct {
    // ... existing fields ...

    // EncryptionPrivateKeyRef is a reference to a Secret containing an age
    // X25519 private key for decrypting the backup. If set, this overrides
    // the BSL's encryptionPrivateKeyRef for this restore operation.
    // +optional
    EncryptionPrivateKeyRef *corev1api.SecretKeySelector `json:"encryptionPrivateKeyRef,omitempty"`
}
```

The restore controller resolves the private key in this order:
1. `restore.Spec.EncryptionPrivateKeyRef` (per-restore override)
2. `bsl.Spec.ObjectStorage.EncryptionPrivateKeyRef` (BSL default)
3. If neither is set and the backup is encrypted, fail with a clear error

#### CLI Flag

```bash
velero restore create --from-backup latest-playground \
  --include-namespaces playground \
  --encryption-private-key private-key.txt
```

When `--encryption-private-key` is specified, the CLI:
1. Reads the age private key from the file
2. Creates a temporary Secret named `velero-restore-enc-<restore-name>` in the
   velero namespace
3. Sets `restore.Spec.EncryptionPrivateKeyRef` pointing to that Secret
4. Sets an owner reference from the Secret to the Restore CR, so the Secret is
   garbage collected when the Restore is deleted

This reduces the high-security restore flow to a single command.

### Backward Compatibility

The `age` format begins with the ASCII header `age-encryption.org/v1\n`. On read,
the first bytes are inspected:

- If the data starts with the age header, decrypt using the configured identities
- Otherwise, return a passthrough reader (legacy unencrypted object)

This allows an encryption-enabled BSL to read backups created before encryption
was configured.

### Disaster Recovery

Full cluster loss. You have S3 access and the private key (stored externally).

```bash
# Download the encrypted backup from S3
aws s3 cp s3://my-velero-backups/backups/my-backup/my-backup.tar.gz \
  encrypted-backup.tar.gz \
  --endpoint-url https://s3.de-west-1.psmanaged.com

# Decrypt with the standard age CLI
age -d -i private-key.txt encrypted-backup.tar.gz > backup.tar.gz

# The tarball contains standard velero backup contents
tar tzf backup.tar.gz
```

No custom tooling required. The `age` CLI is a single static binary available
for all major platforms.

### Implementation

| File | Change |
|------|--------|
| `pkg/apis/velero/v1/backupstoragelocation_types.go` | Add `EncryptionPublicKeyRef`, `EncryptionPrivateKeyRef` fields; update `Validate()` |
| `pkg/apis/velero/v1/restore_types.go` | Add `EncryptionPrivateKeyRef` field to `RestoreSpec` |
| `pkg/persistence/encryption.go` | New: `newEncryptingReader`, `newDecryptingReader` using `filippo.io/age` |
| `pkg/persistence/object_store.go` | Resolve keys in `Get()`, hold parsed age types on `objectBackupStore`, wrap Put/Get |
| `pkg/builder/backup_storage_location_builder.go` | Add `EncryptionPublicKeyRef()`, `EncryptionPrivateKeyRef()` builder methods |
| `pkg/builder/restore_builder.go` | Add `EncryptionPrivateKeyRef()` builder method |
| `pkg/cmd/cli/restore/create.go` | Add `--encryption-private-key` flag; create temp Secret with owner ref |
| `config/crd/v1/bases/velero.io_backupstoragelocations.yaml` | Regenerated via `make update-crd` |
| `config/crd/v1/bases/velero.io_restores.yaml` | Regenerated via `make update-crd` |
| `pkg/apis/velero/v1/zz_generated.deepcopy.go` | Regenerated |
| `go.mod` | Add `filippo.io/age` dependency |

No object storage plugin changes. The plugin receives and returns byte streams;
Velero wraps those streams with age encryption/decryption.

### Key Resolution

In `objectBackupStoreGetter.Get()`, after the existing `caCertRef` block:

```go
var encryptionRecipients []age.Recipient
var encryptionIdentities []age.Identity

if location.Spec.ObjectStorage.EncryptionPublicKeyRef != nil {
    if b.secretStore == nil {
        return nil, errors.New("secret store required for encryptionPublicKeyRef but not available")
    }
    pubKeyStr, err := b.secretStore.Get(location.Spec.ObjectStorage.EncryptionPublicKeyRef)
    if err != nil {
        return nil, errors.Wrap(err, "error getting encryption public key from secret")
    }
    recipient, err := age.ParseX25519Recipient(strings.TrimSpace(pubKeyStr))
    if err != nil {
        return nil, errors.Wrap(err, "error parsing age public key")
    }
    encryptionRecipients = []age.Recipient{recipient}
}

if location.Spec.ObjectStorage.EncryptionPrivateKeyRef != nil {
    if b.secretStore == nil {
        return nil, errors.New("secret store required for encryptionPrivateKeyRef but not available")
    }
    privKeyStr, err := b.secretStore.Get(location.Spec.ObjectStorage.EncryptionPrivateKeyRef)
    if err != nil {
        return nil, errors.Wrap(err, "error getting encryption private key from secret")
    }
    identity, err := age.ParseX25519Identity(strings.TrimSpace(privKeyStr))
    if err != nil {
        return nil, errors.Wrap(err, "error parsing age private key")
    }
    encryptionIdentities = []age.Identity{identity}
}
```

### BSL Controller Warning

During reconciliation, if a BSL has `EncryptionPublicKeyRef` set but
`EncryptionPrivateKeyRef` is nil, the controller logs:

```go
if location.Spec.ObjectStorage.EncryptionPublicKeyRef != nil &&
    location.Spec.ObjectStorage.EncryptionPrivateKeyRef == nil {
    log.Warn("BSL has encryption enabled but no private key — restores will require manual key injection")
}
```

## Security Considerations

- **S3 compromise only**: attacker gets ciphertext, has no key — backups are safe
- **Cluster compromise only (high-security mode)**: attacker gets the public key
  only — cannot decrypt existing backups
- **Cluster compromise only (convenience mode)**: attacker gets both keys — can
  decrypt if they also obtain the ciphertext from S3
- **Both compromised**: full access regardless of encryption
- `age` uses authenticated encryption (ChaCha20-Poly1305 in STREAM construction),
  preventing silent corruption or tampering
- The private key must be stored outside the cluster in a location of the
  operator's choosing (1Password, printed sheet, USB key, etc.) to enable
  disaster recovery

## Limitations

- `velero backup download` produces ciphertext (signed URL bypasses Velero);
  decrypt locally with `age -d -i key.txt`
- Key rotation requires re-encrypting existing backup objects (out of scope)
- Kopia volume backups are unaffected; configure Kopia's own encryption separately
- ChaCha20-Poly1305 is not FIPS-approved (AES-256-GCM is)

## Testing

### Unit Tests

**`pkg/persistence/encryption_test.go`** (new):
- Encrypt/decrypt round-trip (small data)
- Encrypt/decrypt round-trip (>1 MiB, streaming)
- Empty data round-trip
- Decrypt of unencrypted data passes through (backward compat)
- Short data (<header length) passes through
- Tampered ciphertext fails authentication
- Wrong private key fails decryption
- Decrypt with no identities returns clear error
- Encrypted data starts with age header
- Multiple recipients: either private key can decrypt

**`pkg/persistence/object_store_test.go`** (additions):
- Put with encryption: raw stored bytes differ from plaintext
- Get with encryption: round-trips correctly
- Get with encryption on unencrypted legacy data: passthrough
- Put with public key only: encrypts successfully
- Get with public key only (no private key): returns error
- No encryption: unchanged behaviour

**`pkg/apis/velero/v1/backupstoragelocation_types_test.go`** (additions):
- Valid: only `EncryptionPublicKeyRef` set
- Valid: both encryption refs set
- Invalid: only `EncryptionPrivateKeyRef` set (no public key)
- Valid: encryption refs with CACertRef (orthogonal features)

**`pkg/cmd/cli/restore/create_test.go`** (new):
- `--encryption-private-key` flag sets `EncryptionPrivateKeyFile` on CreateOptions
- Validate rejects non-existent key file

### E2E Tests

Follow the `bsl-mgmt` pattern:
1. Generate an age keypair
2. Create Secrets for public and private keys
3. Create BSL with both refs
4. Run backup, verify raw stored object starts with `age-encryption.org/v1`
5. Restore and verify data integrity
6. Remove private key Secret, verify restore fails with clear error

## Alternatives Considered

### Custom VLRE Format (Symmetric AES-256-GCM)

The initial design used a custom chunked AES-256-GCM format with a `VLRE` magic
header. Rejected because:
- Custom format requires custom tooling for disaster recovery
- Symmetric key in cluster means cluster compromise exposes all backups
- Maintaining custom crypto is a liability

### rclone Proxy

Runs rclone as a transparent S3 proxy. Requires pinned plugin version ≤ v1.9.0,
incompatible with our v1.12.0.

### SSE-C

Server-side encryption with customer-provided keys. Does not protect against
compromised S3 credentials (the key is sent with every request).

### Exclude Secrets from Backups

Complementary but insufficient: sensitive data also appears in ConfigMaps, CRDs,
and other resources.
