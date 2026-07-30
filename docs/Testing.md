# Testing and Operations

## Common cryptographic tests

Run from Windows PowerShell 5.1:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File .\Tests\Test-WinPECredentialTransfer.ps1
```

This test does not require elevation and does not modify the registry. It checks:

- UUID-and-serial key derivation.
- UUID-only key derivation.
- Serial-only key derivation.
- Random-secret-only key derivation.
- Encryption and decryption round trips.
- Package-tampering rejection.
- Placeholder hardware-value rejection.
- Single-credential array handling.
- Transfer-ID validation.
- Enforcement of requirements authenticated inside the payload.

Successful completion ends with:

```text
ALL COMMON CRYPTOGRAPHIC TESTS PASSED
```

## Full-OS integration test

Run from an elevated Windows PowerShell 5.1 session:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File .\Tests\Test-WinPECredentialTransfer.FullOS.ps1
```

The test pauses at checkpoints so the operator can inspect each artifact. It
prints exact paths and ready-to-run inspection commands.

It validates:

- Temporary transfer creation below live `HKLM:\SOFTWARE`.
- Registry values and ACL protection.
- Ownership-marker and engine-version consistency.
- Rejection of reads with incomplete ownership metadata.
- Existing-artifact collision rejection.
- Rejection of direct cleanup against an unrelated file.
- Registry preservation when a locked package cannot be removed.
- Preservation and rollback of an existing transfer when overwrite fails.
- Successful overwrite with a new transfer ID, protected final ACL, authenticated
  replacement package, and no retained transaction backups.
- Explicit `Committed` and `CleanupComplete` result contracts.
- Absence of the dummy username and password from registry values.
- Wrong-machine rejection when hardware binding is available.
- Modified-package rejection.
- Restoration of the original package after the tampering test.
- Full import and DPAPI CLIXML creation.
- Transactional restoration of existing CLIXML when a later commit fails.
- CLIXML username and password round trip.
- Package and bootstrap-key cleanup.

Use `-NoPause` for automation:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File .\Tests\Test-WinPECredentialTransfer.FullOS.ps1 -NoPause
```

The full-OS test uses:

```text
HKLM:\SOFTWARE\WinPECredentialTransfer\Tests\<GUID>
%TEMP%\WPCT-FullOS-<GUID>
```

It uses dummy credentials and removes its artifacts in a `finally` block.

The full-OS test must be run again after changes to ACL handling, registry
metadata, package creation, import, cleanup, or DPAPI export.

## WinPE acceptance test

Before production deployment, boot the actual supported WinPE image and verify:

```powershell
$PSVersionTable.PSVersion
Get-Command Get-CimInstance, Get-Acl, Set-Acl, Export-Clixml
Get-CimInstance Win32_BIOS
Get-CimInstance Win32_ComputerSystemProduct
Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\MiniNT'
```

Then create a transfer with `New-WPCTTransfer.ps1`, boot the same device into
the installed Windows system, and import it with `Import-WPCTTransfer.ps1`.
Repeat this acceptance test for each supported ADK/WinPE build and representative
hardware family.

The common regression suite also verifies registry-subkey confinement and the
required cleanup ownership contract. The elevated integration suite confirms
that incomplete ownership metadata cannot remove either transfer artifact.

## Production checklist

Before creation in WinPE:

- Confirm the installed Windows path.
- Select a deployment-specific registry subkey.
- Select the final `.bin` package path.
- Confirm every required credential is present.
- Ensure the offline hive is not already mounted.

For normal operation, prefer `New-WPCTTransfer.ps1`; it performs environment
validation and manages the offline-hive lifecycle automatically.

After creation:

- Confirm `Success` is true.
- Record the returned binding mode for diagnostics.
- Verify the `.bin` file exists.
- Always unload the offline hive.

Before import in full Windows:

- Run under the account that must own the CLIXML files.
- Confirm the expected package path and registry subkey.
- Provide `RequiredSecretIds`.
- Protect the output directory with suitable NTFS ACLs.

For normal operation, prefer `Import-WPCTTransfer.ps1`; it rejects WinPE and
reports the DPAPI owner, output paths, and cleanup result.

After import:

- Confirm `Success` is true.
- Confirm every returned CLIXML path exists.
- Confirm `CleanedUp` is true unless retention was requested.
- Restrict access to the CLIXML files.

## Troubleshooting

### Package authentication failed

Likely causes:

- The package and registry key came from different creation runs.
- A selected UUID or serial value changed or is unavailable.
- The package was modified.
- The bootstrap secret was modified.

Do not retry with weakened validation. Recreate the transfer from a trusted
deployment environment.

### Binding field unavailable

A hardware field selected during WinPE cannot be reproduced in full Windows.
Check firmware reporting, CIM availability, and device-service history.

### CLIXML cannot be decrypted

The file was likely created under a different Windows account or Windows
installation. Re-run the transfer import under the intended consumer identity.

### Offline hive cannot be unloaded

Ensure no registry handles remain open. The engine requests garbage collection
before calling `reg.exe unload`, but external processes can still retain handles.

### Cleanup reports failure

Inspect the exact package and registry paths returned by the engine. Remove only
those specific artifacts after confirming they belong to the intended transfer.

### Registry key at the specified path does not exist

Confirm that the installed `SOFTWARE` hive was mounted successfully and that the
wrapper returned a valid `RegistryRoot`. The engine creates missing parent
subkeys, but it cannot write beneath a hive that is not mounted.

### Existing package or registry key

The engine refuses silent replacement. Use a unique path/subkey, clean the
confirmed prior transfer, or use the overwrite switch only when replacement is
intentional and the existing registry key has a valid ownership marker.
