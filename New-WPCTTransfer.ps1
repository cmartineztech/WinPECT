#requires -Version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
    Creates a WinPE Credential Transfer package from Windows PE.
.DESCRIPTION
    Verifies that the script is running in Windows PE, prompts for the requested
    credentials, mounts the installed Windows SOFTWARE hive, creates the
    protected transfer, and always attempts to unload the hive.

    All cryptography and registry operations are provided by the shared
    WinPECredentialTransfer.ps1 engine.
.PARAMETER WindowsPath
    Path to the installed Windows directory.
.PARAMETER SecretFilePath
    Destination path for the encrypted binary transfer package.
.PARAMETER RegistrySubKey
    Bootstrap subkey written into the installed Windows SOFTWARE hive.
.PARAMETER SecretIds
    Unique IDs for credentials to prompt for. Each ID becomes a CLIXML filename
    during full-Windows import.
.PARAMETER RequiredSecretIds
    Credential IDs that must exist in the authenticated payload.
.PARAMETER Metadata
    Optional serializable deployment metadata.
.PARAMETER AllowOverwrite
    Intentionally replaces an existing package and engine-owned registry key.
.PARAMETER SkipEnvironmentCheck
    Allows controlled full-OS testing. Do not use in normal deployment.
.EXAMPLE
    .\New-WPCTTransfer.ps1 `
        -WindowsPath 'C:\Windows' `
        -SecretFilePath 'C:\Deployment\CredentialTransfer.bin' `
        -RegistrySubKey 'Company\CredentialTransfer' `
        -SecretIds 'DeploymentShare','ApplicationInstall' `
        -RequiredSecretIds 'DeploymentShare'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$WindowsPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SecretFilePath,

    [string]$RegistrySubKey = 'WinPECredentialTransfer\Bootstrap',

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string[]]$SecretIds,

    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string[]]$RequiredSecretIds = @(),

    [object]$Metadata = $null,

    [switch]$AllowOverwrite,

    [switch]$SkipEnvironmentCheck
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$enginePath = Join-Path $PSScriptRoot 'WinPECredentialTransfer.ps1'
if (-not (Test-Path -LiteralPath $enginePath -PathType Leaf)) {
    throw "Shared engine not found: $enginePath"
}
. $enginePath

$isWinPE = Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\MiniNT'
if (-not $isWinPE -and -not $SkipEnvironmentCheck) {
    throw 'This creation wrapper must run in Windows PE. Use -SkipEnvironmentCheck only for controlled testing.'
}

$duplicateIds = @(
    $SecretIds |
        Group-Object |
        Where-Object Count -gt 1 |
        Select-Object -ExpandProperty Name
)
if ($duplicateIds.Count -gt 0) {
    throw "Duplicate SecretIds are not allowed: $($duplicateIds -join ', ')"
}

$missingRequiredIds = @($RequiredSecretIds | Where-Object { $_ -notin $SecretIds })
if ($missingRequiredIds.Count -gt 0) {
    throw "RequiredSecretIds were not requested: $($missingRequiredIds -join ', ')"
}

$secrets = New-Object System.Collections.Generic.List[object]
foreach ($id in $SecretIds) {
    $credential = Get-Credential -Message "Enter the credential for '$id'"
    if ($null -eq $credential) {
        throw "Credential collection was cancelled for '$id'."
    }

    $secrets.Add([pscustomobject]@{
        Id         = $id
        Credential = $credential
    })
}

$mountName = 'WPCTOffline_{0}' -f [guid]::NewGuid().ToString('N')
$mount = $null
$result = $null

try {
    $mount = Mount-WPCTOfflineSoftwareHive `
        -WindowsPath $WindowsPath `
        -MountName $mountName

    if (-not $mount.Success) {
        throw $mount.Error
    }

    $result = New-WPCTCredentialTransfer `
        -Secrets $secrets.ToArray() `
        -SecretFilePath $SecretFilePath `
        -OfflineRegistryRoot $mount.Payload.RegistryRoot `
        -RegistrySubKey $RegistrySubKey `
        -RequiredSecretIds $RequiredSecretIds `
        -Metadata $Metadata `
        -AllowOverwrite:$AllowOverwrite

    if (-not $result.Success) {
        throw $result.Error
    }

    Write-Host 'WinPE credential transfer created successfully.' -ForegroundColor Green
    $result.Payload | Format-List
}
finally {
    foreach ($secret in $secrets) {
        $secret.Credential = $null
    }

    if ($null -ne $mount -and $mount.Success) {
        $unmount = Dismount-WPCTOfflineSoftwareHive -MountName $mountName
        if (-not $unmount.Success) {
            Write-Warning "Offline hive cleanup failed: $($unmount.Error)"
        }
    }
}
