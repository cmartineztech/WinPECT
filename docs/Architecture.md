# Architecture and Data Flow

## Purpose

The WinPE Credential Transfer Engine transfers credentials across the boundary
between WinPE and the installed Windows operating system. It avoids placing
plaintext credentials in deployment scripts, command lines, or registry values.

The engine is implemented in `WinPECredentialTransfer.ps1` and supports Windows
PowerShell 5.1.

## Components

The core solution contains three operational files:

| File | Responsibility |
|---|---|
| `New-WPCTTransfer.ps1` | WinPE-only creation entry point |
| `Import-WPCTTransfer.ps1` | Full-Windows import entry point |
| `WinPECredentialTransfer.ps1` | Shared security and workflow engine |

The shared engine contains five logical sections:

1. Common result, validation, random-byte, and memory-clearing helpers.
2. Hardware discovery and cryptographic key derivation.
3. Authenticated binary-package encryption and decryption.
4. Offline-registry mounting, bootstrap storage, and ACL protection.
5. Credential creation, reading, CLIXML export, and cleanup workflows.

## WinPE creation phase

The caller mounts the installed Windows `SOFTWARE` hive and calls
`New-WPCTCredentialTransfer`.

The engine then:

1. Validates credential IDs and required credentials.
2. Reads usable SMBIOS UUID and BIOS serial values.
3. Generates a cryptographically random 32-byte bootstrap secret.
4. Derives independent 32-byte encryption and authentication keys.
5. Serializes the credential payload as compressed UTF-8 JSON.
6. Encrypts the JSON and authenticates the package.
7. Writes the package to a temporary file.
8. Protects the temporary file with SYSTEM/Administrators-only ACLs.
9. Creates a protected key in the offline `SOFTWARE` hive.
10. Stores the random secret, binding-field names, ownership ID, and versions.
11. Atomically moves the temporary package to the requested `.bin` path.

If creation fails, the engine removes the temporary file and any registry key
created during that attempt.

## Full-Windows import phase

The caller runs `Invoke-WPCTCredentialImport` under the Windows account that
must later decrypt the CLIXML files.

The engine then:

1. Reads the bootstrap secret and binding-field names from
   `HKLM:\SOFTWARE`.
2. Verifies the transfer ID, registry schema, and engine-version ownership
   marker.
3. Re-reads the selected hardware values.
4. Re-derives the encryption and authentication keys.
5. Authenticates the complete binary package.
6. Decrypts the payload only after authentication succeeds.
7. Validates the payload schema, secret IDs, and required-secret list.
8. Exports each credential as a DPAPI-protected CLIXML file.
9. Re-imports each CLIXML file to verify its type and username.
10. Removes the `.bin` package and registry bootstrap key unless
   `-KeepTransfer` was supplied.

## Binary package format

Binary package version 3 uses this layout:

| Offset | Length | Content |
|---:|---:|---|
| 0 | 4 | ASCII magic value `WPCT` |
| 4 | 1 | Package version (`3`) |
| 5 | 16 | AES initialization vector |
| 21 | 32 | HMAC-SHA-256 authentication tag |
| 53 | variable | AES-256-CBC ciphertext |

The authenticated data is the magic value, version, IV, and ciphertext. The
authentication tag itself is not included in the authenticated input.

The package filename extension is `.bin` by convention. The format is identified
by its authenticated `WPCT` header and version, not by the extension.

## Payload schema

After decryption, the JSON payload contains:

| Field | Purpose |
|---|---|
| `SchemaVersion` | Payload schema version |
| `EngineVersion` | Engine version that created the payload |
| `TransferId` | Unique identifier authenticated with the payload |
| `CreatedUtc` | UTC creation timestamp |
| `BindingFields` | Hardware fields selected during creation |
| `RequiredSecretIds` | Credentials the caller declared mandatory |
| `Metadata` | Optional caller-provided deployment metadata |
| `Secrets` | Credential records |

Each secret contains an ID, type, username, and password. Secret IDs may contain
letters, numbers, periods, underscores, and hyphens. IDs must be unique because
they become CLIXML filenames.

Engine version 3.0 uses binary package version 3, payload schema 4, and registry
schema 4. These formats intentionally distinguish WPCT transfers from packages
created under previous product identities.

## Result contract

Workflow functions return an object with:

| Property | Meaning |
|---|---|
| `Success` | Boolean outcome |
| `Payload` | Result-specific data on success |
| `Error` | Error message on failure |

Callers should always check `Success` before using `Payload`.

## Failure boundaries

Creation uses a GUID-specific temporary file and moves it into place only after
the package and registry bootstrap data have been created. A failed creation
removes only the temporary file and registry key owned by that transfer.

CLIXML export uses a protected staging directory. Existing files are not
replaced unless overwrite is explicitly enabled. If commit fails, newly moved
files are removed and backed-up files are restored.
