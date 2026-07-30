# Version and Compatibility

## Current format

WinPE Credential Transfer 3.0 uses:

| Component | Identifier |
|---|---|
| Engine version | `3.0.0` |
| PowerShell prefix | `WPCT` |
| Binary magic | `WPCT` |
| Binary package version | `3` |
| Payload schema | `4` |
| Registry schema | `4` |
| Ownership property | `TransferId` |
| Default registry subkey | `WinPECredentialTransfer\Bootstrap` |

## Compatibility rule

The creating and importing environments must use the same WPCT engine release.
Copy the shared engine and both wrappers together:

```text
WinPECredentialTransfer.ps1
New-WPCTTransfer.ps1
Import-WPCTTransfer.ps1
```

Do not replace only one copy during an active deployment.

## Previous formats

Packages created under previous product names, command prefixes, binary magic
values, derivation contexts, payload schemas, or registry schemas are
intentionally incompatible with WPCT 3.0.

There is no migration operation for an encrypted transfer. Recreate it:

1. Remove the old test/deployment artifacts after confirming their ownership.
2. Deploy the WPCT 3.0 engine and wrappers together.
3. Create a new `.bin` transfer in WinPE.
4. Import it with the same WPCT 3.0 engine in full Windows.

## Windows requirements

The shared engine targets Windows PowerShell 5.1.

For WinPE, include:

1. `WinPE-WMI`
2. `WinPE-NetFX`
3. `WinPE-Scripting`
4. `WinPE-PowerShell`

For full Windows, run the import under the identity that must own the resulting
DPAPI-protected CLIXML files.

## Operational compatibility

- Package paths may use any extension; `.bin` is the documented convention.
- Existing binary package, payload, and registry schema formats are unchanged by
  the path and cleanup hardening.
- Registry subkeys must be relative and cannot contain traversal, provider, or
  wildcard syntax.
- Direct cleanup now requires the authenticated transfer ID.
- Filesystem paths containing reparse points are intentionally rejected.
- Secret IDs are limited to letters, numbers, periods, underscores, and hyphens.
- Hardware binding depends on stable SMBIOS UUID and/or BIOS serial reporting.
- Systems with neither valid hardware value use the protected random secret
  without hardware binding.
- CLIXML created by one Windows identity normally cannot be decrypted by another
  identity or another Windows installation.
