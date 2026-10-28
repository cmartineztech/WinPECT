# Security Model

## Security goals

The engine is designed to:

- Keep plaintext credentials out of registry values and the `.bin` package.
- Detect modification before attempting decryption.
- Make the registry bootstrap secret accessible only to local SYSTEM and local
  Administrators.
- Optionally bind package recovery to stable machine identifiers.
- Minimize the lifetime of the transfer artifacts.
- Convert recovered credentials into Windows DPAPI-protected CLIXML.
- Reject reads when registry ownership metadata is incomplete or belongs to a
  different engine version.
- Refuse unmarked registry-key deletion and silent artifact replacement.

## Threat model

The transfer is intended to protect credentials from casual disclosure,
artifact theft involving only one half of the transfer, accidental logging, and
unauthorized modification. It assumes the creation and import processes are
trusted while they run.

It does not protect against an attacker who controls WinPE, controls the
full-Windows import process, or has local SYSTEM/administrator access to both
the `.bin` package and bootstrap registry data.

## Security improvement over unattended files

An unattended deployment file that contains a reusable plaintext password, or
a password protected only by reversible encoding, can expose that credential to
anyone who can read the file. Copies may also remain in deployment shares,
images, backups, or diagnostic artifacts.

WPCT reduces that exposure by avoiding plaintext credential storage in the
unattended file and by using several controls together:

| Risk | Plaintext unattended file | WPCT control |
|---|---|---|
| A single readable file reveals the password | Often yes | The package is encrypted and the random bootstrap secret is stored separately |
| Offline modification goes unnoticed | Often possible | HMAC authentication rejects modified packages before decryption |
| Artifact is copied to another computer | Credential remains readable | Available hardware values can participate in key derivation |
| Broad inherited access | Depends on deployment storage | Sensitive registry keys, files, and directories receive restricted ACLs |
| Credential remains after setup | Common unless separately removed | Successful import removes temporary package and registry data |
| Long-term credential file is portable | Plaintext remains portable | CLIXML is protected by DPAPI for the importing identity and Windows installation |

These controls provide defense in depth; they do not turn a reusable password
into a non-secret or defeat a trusted-context compromise. Prefer eliminating
password transfer entirely when certificate bootstrap, device identity,
Offline Domain Join, or post-startup retrieval from a secrets manager is
available.

## Cryptography

The engine uses:

- `RandomNumberGenerator` for the 32-byte bootstrap secret and 16-byte IV.
- HKDF-HMAC-SHA-256 for key derivation.
- Separate 32-byte encryption and authentication keys.
- AES-256-CBC with PKCS#7 padding for encryption.
- HMAC-SHA-256 over the package header, version, IV, and ciphertext.
- A fixed-time comparison for authentication tags of equal length.

Authentication is checked before decryption.

The design is encrypt-then-MAC: the engine verifies HMAC-SHA-256 before invoking
AES decryption.

## Hardware binding

The derivation context can contain:

- SMBIOS UUID
- BIOS serial number
- Both values
- Neither value

Only normalized, non-placeholder values are used. The exact selected field names
are recorded in the registry and authenticated inside the payload.

Hardware identifiers are not secrets. They add machine binding but do not
replace the random bootstrap secret or registry ACLs.

## Registry ACL

The bootstrap key (and any parent subkeys under `SOFTWARE` created by `WinPECT`):

- Disables inherited access rules.
- Grants full control to `NT AUTHORITY\SYSTEM` (`S-1-5-18`).
- Grants full control to local `Administrators` (`S-1-5-32-544`).
- Applies the hardened DACL first and sets local `Administrators` as owner on a best-effort basis so elevated split-token administrators without `SeRestorePrivilege` still lock down the DACL.

## Logging and Memory Hygiene

- `Assert-WPCTSafeLogging` blocks credential creation, reading, export, and import when PowerShell Transcription or Script Block Logging policies (including `WOW6432Node`) or `$global:Transcript` are active.
- `ConvertTo-WPCTSerializableSecrets` extracts `PSCredential` secrets via `Marshal::SecureStringToBSTR` and zeroes the unmanaged BSTR in `finally` via `Marshal::ZeroFreeBSTR`.
- `Read-WPCTCredentialTransfer` attaches `SecurePassword` (`SecureString`) and `Credential` (`PSCredential`) properties to each secret entry, and `Clear-WPCTPayloadSecrets` deterministically scrubs `.Password`, `.SecurePassword`, and `.Credential` in `finally`.

## Artifact sensitivity

The encrypted `.bin` package and registry bootstrap secret must be protected as
a pair:

- The `.bin` file alone should not reveal credentials.
- The registry secret alone does not contain credentials.
- Possession of both artifacts on the correctly bound machine enables recovery.

Do not retain either artifact longer than necessary.

## Ownership and collision protection

Each transfer receives a GUID ownership marker authenticated inside the package
and stored in the registry. Creation refuses existing files and keys by default.
Cleanup refuses registry keys without a valid marker and refuses a caller-
supplied ownership mismatch. Temporary package filenames include the transfer
GUID so concurrent runs do not share a `.tmp` path.

Package files are restricted to SYSTEM and local Administrators. CLIXML staging
and output directories are restricted to the creating identity, SYSTEM, and
local Administrators.

## DPAPI ownership

`Export-Clixml` protects a `PSCredential` for the account running the export:

- Export under SYSTEM when later automation runs as SYSTEM.
- Export under a specific administrator when that administrator consumes it.
- Do not expect another account or another Windows installation to decrypt it.

## Memory limitations

The engine clears sensitive byte arrays where practical. PowerShell, .NET,
JSON strings, and immutable strings can still leave transient copies in managed
memory until garbage collection. This engine reduces exposure but cannot
guarantee complete memory erasure.

## Operational limitations

- Administrator access can read the protected bootstrap key.
- Compromise of the running WinPE or Windows process can expose credentials.
- Hardware values may be missing, duplicated, or change after firmware/service
  operations.
- The engine does not provide remote transport or long-term secret storage.
- CLIXML files remain sensitive and require appropriate filesystem ACLs.
- `-KeepTransfer` extends the exposure window and should be used only when needed.
- `-AllowOverwrite` replaces an existing owned registry transfer and package.
  The existing transfer ID, schema, and engine version must be valid. Use it
  only after confirming the exact paths belong to the intended transfer. The
  prior artifacts remain protected transaction backups until commit. Backup and
  final registry keys are created with protected ACLs and verified before their
  source keys are removed.
- `-AllowClixmlOverwrite` replaces existing credential files. Preserve any
  required recovery copy before using it. An incomplete rollback retains its
  protected backup directory and reports the recovery path.
- Applying the credential-directory ACL replaces inheritance on the selected
  output directory. Use a dedicated credential directory rather than a shared
  application directory.
- Direct cleanup requires a caller-supplied authenticated `TransferId` and
  verifies both the complete registry ownership marker and the encrypted package
  before deleting any artifact. Prefer `Invoke-WPCTCredentialImport`, which
  supplies the authenticated ID.
- Cleanup preserves the registry bootstrap secret when temporary-file or package
  removal fails, allowing the failure to be diagnosed without silently
  destroying the remaining key material.
- Creation and CLIXML export return success only after transaction staging and
  backup artifacts are verified absent. A committed operation with incomplete
  cleanup returns failure with its retained recovery paths.
- Registry subkeys must remain relative to the selected `SOFTWARE` hive.
  Traversal syntax, provider paths, wildcards, and empty segments are rejected.
- Package and credential-output paths containing filesystem reparse points are
  rejected to prevent elevated operations from being redirected.

## Recommended controls

- Run the creation and import phases in controlled deployment environments.
- Store the `.bin` package on a local, access-controlled volume.
- Require expected credential IDs during both creation and import.
- Run import immediately after Windows starts.
- Allow normal cleanup after successful import.
- Protect the CLIXML output directory with least-privilege NTFS ACLs.
- Test firmware and hardware-identifier behavior on supported device families.
- Use the full-OS integration test before deployment changes are released.
- Use separate, least-privilege deployment identities rather than general
  administrator accounts.
- Prefer short-lived credentials and rotate them after deployment.
- When possible, avoid transfer entirely by using certificate bootstrap,
  Offline Domain Join, Windows LAPS, or post-startup secret retrieval.

## Security disclaimer

No software design can guarantee that credentials will never be exposed. This
project is provided as-is under the MIT License, without warranty. Operators
must validate the engine, WinPE image, Windows build, filesystem and registry
permissions, hardware-binding behavior, logging configuration, and deployment
account scope for their own environment before production use.
