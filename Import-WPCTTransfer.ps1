#requires -Version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
    Imports a WinPE Credential Transfer package in full Windows.
.DESCRIPTION
    Verifies that the script is running in the installed Windows environment,
    authenticates and decrypts the transfer, creates DPAPI-protected CLIXML files
    for the current Windows identity, and normally removes the transfer.

    All cryptography and cleanup operations are provided by the shared
    WinPECredentialTransfer.ps1 engine.
.PARAMETER SecretFilePath
    Path to the encrypted binary transfer package.
.PARAMETER OutputDirectory
    Destination for DPAPI-protected credential CLIXML files.
.PARAMETER RegistrySubKey
    Bootstrap subkey below the installed `HKLM:\SOFTWARE` hive.
.PARAMETER RequiredSecretIds
    Credential IDs required by the full-Windows consumer.
.PARAMETER KeepTransfer
    Retains the binary package and registry key after a successful import.
.PARAMETER AllowClixmlOverwrite
    Intentionally replaces existing credential CLIXML files.
.PARAMETER SkipEnvironmentCheck
    Reserved for controlled testing. Normal imports must run outside WinPE.
.EXAMPLE
    .\Import-WPCTTransfer.ps1 `
        -SecretFilePath 'C:\Deployment\CredentialTransfer.bin' `
        -OutputDirectory 'C:\ProgramData\Company\Credentials' `
        -RegistrySubKey 'Company\CredentialTransfer' `
        -RequiredSecretIds 'DeploymentShare'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SecretFilePath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory,

    [string]$RegistrySubKey = 'WinPECredentialTransfer\Bootstrap',

    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string[]]$RequiredSecretIds = @(),

    [switch]$KeepTransfer,

    [switch]$AllowClixmlOverwrite,

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
if ($isWinPE -and -not $SkipEnvironmentCheck) {
    throw 'This import wrapper must run in the installed Windows environment, not Windows PE.'
}

$result = Invoke-WPCTCredentialImport `
    -SecretFilePath $SecretFilePath `
    -OutputDirectory $OutputDirectory `
    -RegistrySubKey $RegistrySubKey `
    -RequiredSecretIds $RequiredSecretIds `
    -KeepTransfer:$KeepTransfer `
    -AllowClixmlOverwrite:$AllowClixmlOverwrite

if (-not $result.Success) {
    throw $result.Error
}

Write-Host 'Credential transfer imported successfully.' -ForegroundColor Green
Write-Host "DPAPI identity: $($result.Payload.CreatedFor)"
Write-Host "Transfer ID: $($result.Payload.TransferId)"
Write-Host "Cleaned up: $($result.Payload.CleanedUp)"
Write-Host 'Credential files:'
$result.Payload.ClixmlFiles | ForEach-Object {
    Write-Host "  $_"
}

$result.Payload
