# Function Reference

Dot-source the engine before calling its functions:

```powershell
. .\WinPECredentialTransfer.ps1
```

## Operational entry scripts

All entry scripts dot-source `WinPECredentialTransfer.ps1`. Keep the shared
engine in the same directory as the selected wrapper.

### `New-WPCTTransfer.ps1`

Recommended WinPE interface. It verifies the WinPE environment, prompts for each
requested credential, mounts the offline `SOFTWARE` hive with a unique name,
calls `New-WPCTCredentialTransfer`, and unloads the hive in `finally`.

Use `-SecretIds` to define the credential prompts. Use
`-SkipEnvironmentCheck` only for controlled testing outside WinPE.

Parameters:

- `WindowsPath` - installed Windows directory.
- `SecretFilePath` - destination `.bin` path.
- `RegistrySubKey` - bootstrap key relative to the offline `SOFTWARE` hive.
- `SecretIds` - IDs for credentials that the wrapper prompts to collect.
- `RequiredSecretIds` - IDs that must exist in the payload.
- `Metadata` - optional serializable deployment metadata.
- `AllowOverwrite` - explicitly replace existing engine-owned artifacts.
- `SkipEnvironmentCheck` - bypass WinPE detection for controlled testing.

### `Import-WPCTTransfer.ps1`

Recommended full-Windows interface. It rejects WinPE, calls
`Invoke-WPCTCredentialImport`, and reports the DPAPI identity, transfer ID,
created CLIXML files, and cleanup state.

Parameters:

- `SecretFilePath` - encrypted `.bin` transfer path.
- `OutputDirectory` - destination for DPAPI-protected CLIXML.
- `RegistrySubKey` - bootstrap key below `HKLM:\SOFTWARE`.
- `RequiredSecretIds` - IDs required by the consumer.
- `KeepTransfer` - retain the package and registry data after import.
- `AllowClixmlOverwrite` - explicitly replace existing credential XML files.
- `SkipEnvironmentCheck` - bypass full-Windows detection for controlled tests.

## Workflow functions

### `Mount-WPCTOfflineSoftwareHive`

Mounts an installed Windows `SOFTWARE` hive beneath `HKLM`.

Parameters:

- `WindowsPath` - installed Windows directory, such as `C:\Windows`.
- `MountName` - temporary `HKLM` mount name. Default: `WPCTOffline`.

The success payload contains `MountName`, `RegistryRoot`, and `HivePath`.
Always dismount the hive in a `finally` block.

### `Dismount-WPCTOfflineSoftwareHive`

Unloads a hive previously mounted by `Mount-WPCTOfflineSoftwareHive`.

Parameters:

- `MountName` - mount name used during loading.

### `New-WPCTCredentialTransfer`

Creates the encrypted `.bin` package and protected registry bootstrap key.

Parameters:

- `Secrets` - one or more credential descriptors.
- `SecretFilePath` - exact destination path for the binary package.
- `OfflineRegistryRoot` - mounted offline hive root, such as
  `HKLM:\WPCTOffline`.
- `RegistrySubKey` - subkey relative to the supplied registry root. Rooted
  provider paths, traversal segments, wildcards, and empty segments are rejected.
- `Metadata` - optional serializable caller data.
- `RequiredSecretIds` - IDs that must exist in the payload.
- `MachineIdentity` - optional identity override, primarily for testing.
- `AllowOverwrite` - explicitly replace an existing package and an existing
  engine-owned bootstrap key. The existing transfer ID, registry schema, and
  engine version must all be valid before the key can be replaced. The previous
  package and registry key remain as protected transaction backups until the
  replacement commits. Registry backups and final keys are copied into freshly
  ACL-protected keys; secret-bearing keys are not renamed.
- `MaximumPackageBytes` - package-size ceiling. Default: 10 MB.

Preferred secret input:

```powershell
[pscustomobject]@{
    Id         = 'DeploymentShare'
    Credential = Get-Credential
}
```

The success payload includes the engine version, transfer ID, package path,
registry path, binding fields, binding mode, secret count, `Committed`, and
`CleanupComplete`. A committed replacement with retained artifacts returns
`Success = false` and the exact recovery paths.

### `Read-WPCTCredentialTransfer`

Reads, authenticates, decrypts, and validates an existing transfer.

Parameters:

- `SecretFilePath` - path to the encrypted package.
- `RegistrySubKey` - safe relative bootstrap key below `HKLM:\SOFTWARE`.
- `RequiredSecretIds` - credential IDs required by the consumer.
- `MachineIdentity` - optional identity override for testing.
- `MaximumPackageBytes` - maximum package size accepted. Default: 10 MB.

This function does not export CLIXML or remove the transfer.
It rejects registry data unless the transfer ID, registry schema, and engine
version form a complete ownership marker.

### `Export-WPCTCredentialClixml`

Exports every credential in a validated payload as DPAPI-protected CLIXML.

Parameters:

- `Payload` - successful payload from `Read-WPCTCredentialTransfer`.
- `OutputDirectory` - destination directory.
- `AllowOverwrite` - transactionally replace existing credential files.

Each filename is `<SecretId>.xml`. Files can normally be decrypted only by the
same account on the same Windows installation. Export occurs in a protected
staging directory and is rolled back if staging or commit fails. Staging,
backup, and destination directories all receive the credential-directory ACL.
Paths containing filesystem reparse points are rejected. If rollback cannot
restore every previous file, `RolledBack` is false and the protected
`BackupDirectory` is retained for manual recovery. Success is returned only
after staging and backup directories are removed and verified absent.

### `Remove-WPCTCredentialTransfer`

Removes the encrypted package, its temporary-file variant, and the bootstrap
registry key.

Parameters:

- `SecretFilePath` - package path.
- `RegistrySubKey` - safe relative bootstrap key below `HKLM:\SOFTWARE`.
- `TransferId` - required authenticated ownership ID. Missing or mismatched
  ownership prevents cleanup.
- `MaximumPackageBytes` - maximum package size accepted during ownership
  authentication. Default: 10 MB.

Cleanup refuses to delete any artifact unless both the registry ownership marker
and encrypted package authenticate to the supplied transfer ID. The temporary
file and package must be removed successfully before the registry secret is
deleted. The result reports each artifact separately.

### `Invoke-WPCTCredentialImport`

Recommended full-Windows entry point. It reads the transfer, exports CLIXML, and
cleans up.

Parameters:

- `SecretFilePath` - encrypted `.bin` package path.
- `OutputDirectory` - CLIXML destination.
- `RegistrySubKey` - bootstrap registry subkey.
- `RequiredSecretIds` - IDs required by the consumer.
- `KeepTransfer` - retain the package and registry key after successful export.
- `AllowClixmlOverwrite` - allow transactional replacement of existing CLIXML.
- `MaximumPackageBytes` - maximum package size accepted. Default: 10 MB.

The success payload contains `ClixmlFiles`, `CreatedFor`, and `CleanedUp`.

## Supporting functions

These functions are public because the engine is dot-sourced, but callers
normally do not need them directly:

- `New-WPCTResult`
- `Resolve-WPCTRegistrySubKey`
- `Assert-WPCTPathHasNoReparsePoint`
- `Read-WPCTBoundedFile`
- `Clear-WPCTByteArray`
- `Clear-WPCTPayloadSecrets`
- `Assert-WPCTSafeLogging`
- `Test-WPCTRegistryTransferMarker`
- `New-WPCTRandomBytes`
- `Test-WPCTFixedTimeEquals`
- `ConvertTo-WPCTNormalizedHardwareValue`
- `Get-WPCTMachineIdentity`
- `Get-WPCTBindingContextBytes`
- `Invoke-WPCTHmacSha256`
- `Invoke-WPCTHkdfSha256`
- `New-WPCTDerivedKeys`
- `Protect-WPCTBytes`
- `Unprotect-WPCTBytes`
- `ConvertTo-WPCTSerializableSecrets`
- `Test-WPCTPayload`
- `Set-WPCTRegistryKeyAcl`
- `New-WPCTRegistryTransferKey`
- `Get-WPCTRegistryTransferKeyData`
- `Copy-WPCTRegistryTransferKey`
- `Set-WPCTFileAcl`
- `Set-WPCTCredentialDirectoryAcl`
- `Test-WPCTRegistryOwnership`

## Default registry values

The default registry subkey is:

```text
WinPECredentialTransfer\Bootstrap
```

Values written beneath it:

| Name | Type | Meaning |
|---|---|---|
| `RandomSecret` | Binary | 32-byte bootstrap secret |
| `BindingFields` | MultiString | Hardware fields selected in WinPE |
| `SchemaVersion` | DWord | Registry schema version |
| `TransferId` | String | Unique cleanup and package ownership marker |
| `EngineVersion` | String | Engine version that created the transfer |

Engine version 3.0 writes binary package version 3, registry schema 4, and
payload schema 4.
