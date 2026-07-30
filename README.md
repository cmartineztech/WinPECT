# WinPE Credential Transfer

Securely move temporary deployment credentials from Windows PE into a newly
installed Windows operating system.

The transfer uses two protected pieces:

- An encrypted package stored on the target drive.
- A bootstrap secret stored in the offline Windows `SOFTWARE` registry hive.

After Windows starts, the credentials are imported as DPAPI-protected
`PSCredential` CLIXML files. A successful import removes the temporary package
and registry data.

> This solution is for temporary deployment credential transfer. It is not a
> password vault or long-term secrets-management system.

## Why Use This Instead of Plaintext Unattended Credentials?

Traditional deployment workflows sometimes place a username and password
directly in an unattended answer file, task-sequence variable, script, or
command line. Anyone who can read that artifact may be able to recover and reuse
the credential. Encoding or hiding a password is not the same as encrypting it.

This engine adds a defense-in-depth layer:

- Plaintext passwords are not written to unattended files, scripts, command
  lines, registry values, or the encrypted package.
- The encrypted package and its random bootstrap secret are stored separately.
- Package modification is detected before decryption.
- Available hardware identifiers can bind recovery to the target computer.
- Registry, package, staging, and credential-output access is restricted.
- Temporary transfer artifacts are removed after a successful import.
- Imported credentials are stored as DPAPI-protected CLIXML for the importing
  Windows identity.

This is meaningfully safer than passing reusable plaintext credentials through
an unattended file, but it is not an absolute security boundary. An attacker
who controls WinPE, the importing process, or local SYSTEM/Administrator access
to both transfer artifacts may still recover the credentials. Use short-lived,
least-privilege deployment accounts and rotate them after deployment.

## Requirements

### Windows PE

- Windows PowerShell 5.1
- Administrator access
- A deployed Windows installation with an accessible `SOFTWARE` hive
- These WinPE optional components, added in dependency order:
  1. `WinPE-WMI`
  2. `WinPE-NetFX`
  3. `WinPE-Scripting`
  4. `WinPE-PowerShell`

### Full Windows

- Windows PowerShell 5.1
- Administrator access
- The same computer on which the transfer was created
- The encrypted package created during the Windows PE phase

## Files You Need

| File | Run from | Purpose |
|---|---|---|
| `New-WPCTTransfer.ps1` | Windows PE | Collects credentials and creates the protected transfer |
| `Import-WPCTTransfer.ps1` | Full Windows | Imports the credentials and removes the temporary transfer |
| `WinPECredentialTransfer.ps1` | Both | Shared transfer engine used by the two wrappers |

Keep all three files together.

## Implementation

The workflow has two phases:

```text
Windows PE                                  Full Windows
----------                                  ------------
Collect credentials                         Read transfer
Create encrypted package        reboot      Verify and decrypt
Write secret to offline registry  ----->    Export DPAPI CLIXML files
                                             Remove temporary artifacts
```

Use the same package path, registry subkey, and secret IDs in both phases.

### 1. Create the Transfer in Windows PE

Open an elevated Windows PowerShell 5.1 session and run:

```powershell
.\New-WPCTTransfer.ps1 `
    -WindowsPath 'C:\Windows' `
    -SecretFilePath 'C:\Deployment\CredentialTransfer.bin' `
    -RegistrySubKey 'Company\CredentialTransfer' `
    -SecretIds 'DeploymentShare','ApplicationInstall' `
    -RequiredSecretIds 'DeploymentShare','ApplicationInstall'
```

The script prompts once for each secret ID. It then:

1. Mounts the installed operating system's offline `SOFTWARE` hive.
2. Creates the encrypted transfer package.
3. Stores the protected bootstrap data in the offline registry.
4. Unmounts the registry hive.

Choose descriptive secret IDs. Each ID becomes the name of its exported CLIXML
file.

### 2. Start Full Windows

Complete the operating-system deployment and boot into the installed Windows
environment.

The encrypted package must remain at the path used in phase 1.

### 3. Import the Credentials

Sign in as the identity that will later use the credential files. Open an
elevated Windows PowerShell 5.1 session and run:

```powershell
.\Import-WPCTTransfer.ps1 `
    -SecretFilePath 'C:\Deployment\CredentialTransfer.bin' `
    -OutputDirectory 'C:\ProgramData\Company\Credentials' `
    -RegistrySubKey 'Company\CredentialTransfer' `
    -RequiredSecretIds 'DeploymentShare','ApplicationInstall'
```

On success, the output directory contains:

```text
C:\ProgramData\Company\Credentials\DeploymentShare.xml
C:\ProgramData\Company\Credentials\ApplicationInstall.xml
```

The import also removes the encrypted package and its bootstrap registry key.

> DPAPI protects the exported files for the identity that runs the import.
> Import as `SYSTEM` when later automation runs as `SYSTEM`.

### 4. Use an Imported Credential

Run this under the same Windows identity that imported the transfer:

```powershell
$credential = Import-Clixml `
    -LiteralPath 'C:\ProgramData\Company\Credentials\DeploymentShare.xml'
```

`$credential` is a standard `PSCredential` object.

## Automation Example

Pass credential objects directly when an orchestration system already collects
them. For advanced workflows, dot-source the engine and use its functions:

```powershell
. .\WinPECredentialTransfer.ps1
```

The supported functions and result contracts are documented in
[docs/API.md](docs/API.md).

## Important Settings

| Setting | Guidance |
|---|---|
| `WindowsPath` | Path to the installed Windows directory as seen from Windows PE |
| `SecretFilePath` | Local NTFS path that remains available after reboot |
| `RegistrySubKey` | Safe relative subkey used by this transfer; use the same value in both phases |
| `SecretIds` | Names of credentials collected in Windows PE |
| `RequiredSecretIds` | Credentials that must exist before creation or import can succeed |
| `OutputDirectory` | Protected directory for the DPAPI CLIXML files |

Do not reuse a package path or registry subkey for concurrent transfers.
Registry subkeys containing traversal syntax, provider paths, or wildcards are
rejected. Package and output paths must not pass through filesystem reparse
points.

## Verify the Setup

Run the non-destructive cryptographic tests:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File .\Tests\Test-WinPECredentialTransfer.ps1
```

Run the elevated full-Windows integration test:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File .\Tests\Test-WinPECredentialTransfer.FullOS.ps1
```

Also complete one real Windows PE-to-Windows test on every supported device or
virtual-machine platform.

## Troubleshooting

| Problem | What to check |
|---|---|
| Package authentication failed | The package, registry data, or hardware identity does not match. Recreate the transfer; do not bypass validation. |
| Registry key was not found | Confirm that phase 1 targeted the correct Windows installation and used the correct registry subkey. |
| Credential file cannot be decrypted | Use the same Windows identity that ran the import. |
| Package or registry key already exists | Use a unique path and subkey, or clean up the confirmed previous transfer before retrying. |
| Offline registry hive cannot be unloaded | Close anything using the mounted hive and retry with the same mount name. |
| A required secret is missing | Use the same required secret ID list in both phases. |

For diagnostic retention only, use `-KeepTransfer` during import. Remove retained
artifacts as soon as troubleshooting is complete.

## Security Guidance

- Use dedicated, least-privilege deployment accounts.
- Do not transfer domain-administrator or other broad administrative
  credentials.
- Keep the package on NTFS so its access controls are preserved.
- Do not place passwords in metadata, logs, transcripts, or command-line
  arguments.
- Treat the exported CLIXML files as sensitive even though they are protected
  with DPAPI.
- Prefer certificates, device identity, managed identity, Offline Domain Join,
  or a centralized secrets manager when those options fit the deployment.

## How It Is Protected

- A cryptographically random 32-byte bootstrap secret is stored separately from
  the encrypted package.
- HKDF-HMAC-SHA-256 derives independent encryption and authentication keys.
- AES-256-CBC encrypts the payload.
- HMAC-SHA-256 detects modification before decryption.
- Available SMBIOS UUID and BIOS serial values bind the transfer to the target
  computer.
- Registry keys, package files, staging directories, and output directories
  receive restricted access controls.
- Transfer IDs prevent unrelated package and registry artifacts from being
  combined or removed accidentally.

For the complete design and security details, see:

- [Architecture and data flow](docs/Architecture.md)
- [Security model](docs/Security.md)
- [Function reference](docs/API.md)
- [Testing and operations](docs/Testing.md)
- [Version compatibility](docs/Compatibility.md)

## License and Disclaimer

This project is available under the [MIT License](LICENSE).

The software is provided **as is**, without warranty of any kind. Security
controls reduce risk but do not guarantee that credentials cannot be exposed.
You are responsible for validating the solution in your own WinPE images,
Windows builds, hardware, deployment workflow, and threat model before
production use.
