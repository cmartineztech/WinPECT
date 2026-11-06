#requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'WinPECredentialTransfer.ps1')

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message
    )

    if (-not $Condition) {
        throw "FAILED: $Message"
    }

    Write-Host "[PASS] $Message" -ForegroundColor Green
}

$cases = @(
    [pscustomobject]@{
        Name = 'UUID and serial'
        Identity = [pscustomobject]@{
            SmbiosUuid   = '4C4C4544-0035-4210-8058-B7C04F4D5032'
            SerialNumber = 'ABC123'
            BindingFields = @('SmbiosUuid', 'SerialNumber')
        }
    },
    [pscustomobject]@{
        Name = 'UUID only'
        Identity = [pscustomobject]@{
            SmbiosUuid   = '4C4C4544-0035-4210-8058-B7C04F4D5032'
            SerialNumber = $null
            BindingFields = @('SmbiosUuid')
        }
    },
    [pscustomobject]@{
        Name = 'Serial only'
        Identity = [pscustomobject]@{
            SmbiosUuid   = $null
            SerialNumber = 'ABC123'
            BindingFields = @('SerialNumber')
        }
    },
    [pscustomobject]@{
        Name = 'Random only'
        Identity = [pscustomobject]@{
            SmbiosUuid   = $null
            SerialNumber = $null
            BindingFields = @()
        }
    }
)

foreach ($case in $cases) {
    [byte[]]$random = New-WPCTRandomBytes 32
    [byte[]]$plain = [Text.Encoding]::UTF8.GetBytes('credential payload test')
    $keys = $null
    $package = $null
    $roundtrip = $null

    try {
        $keys = New-WPCTDerivedKeys $random $case.Identity $case.Identity.BindingFields
        $package = Protect-WPCTBytes $plain $keys.EncryptionKey $keys.MacKey
        $roundtrip = Unprotect-WPCTBytes $package $keys.EncryptionKey $keys.MacKey

        Assert-True (Test-WPCTFixedTimeEquals $plain $roundtrip) "$($case.Name) round trip"

        [byte[]]$tampered = New-Object byte[] $package.Length
        [Array]::Copy($package, $tampered, $package.Length)
        $tampered[$tampered.Length - 1] = $tampered[$tampered.Length - 1] -bxor 1

        $failed = $false
        try {
            Unprotect-WPCTBytes $tampered $keys.EncryptionKey $keys.MacKey | Out-Null
        }
        catch {
            $failed = $true
        }

        Assert-True $failed "$($case.Name) rejects tampering"
        Clear-WPCTByteArray $tampered
    }
    finally {
        Clear-WPCTByteArray $random
        Clear-WPCTByteArray $plain
        Clear-WPCTByteArray $package
        Clear-WPCTByteArray $roundtrip

        if ($null -ne $keys) {
            Clear-WPCTByteArray $keys.EncryptionKey
            Clear-WPCTByteArray $keys.MacKey
        }
    }
}

Assert-True ($null-eq(ConvertTo-WPCTNormalizedHardwareValue 'To Be Filled By O.E.M.' SerialNumber)) 'Placeholder serial omitted'
Assert-True ($null-eq(ConvertTo-WPCTNormalizedHardwareValue 'Not Applicable' SerialNumber)) 'Not Applicable serial omitted'
Assert-True ($null-eq(ConvertTo-WPCTNormalizedHardwareValue 'Invalid' SerialNumber)) 'Invalid serial omitted'
Assert-True ($null-eq(ConvertTo-WPCTNormalizedHardwareValue '0123456789' SerialNumber)) '0123456789 serial omitted'
Assert-True ($null-eq(ConvertTo-WPCTNormalizedHardwareValue '123456789' SerialNumber)) '123456789 serial omitted'
Assert-True ($null-eq(ConvertTo-WPCTNormalizedHardwareValue '00000000-0000-0000-0000-000000000000' SmbiosUuid)) 'Zero UUID omitted'
Assert-True ($null-eq(ConvertTo-WPCTNormalizedHardwareValue '03000200-0400-0500-0006-000700080009' SmbiosUuid)) 'AMI default UUID 03000200 omitted'
Assert-True ($null-eq(ConvertTo-WPCTNormalizedHardwareValue '00020003-0004-0005-0006-000700080009' SmbiosUuid)) 'AMI byte-swapped UUID 00020003 omitted'
Assert-True ($null-eq(ConvertTo-WPCTNormalizedHardwareValue '{03000200-0400-0500-0006-000700080009}' SmbiosUuid)) 'Braced AMI default UUID omitted'

$identityCmd = Get-Command Get-WPCTMachineIdentity
Assert-True ($null -ne $identityCmd.Parameters['MaxAttempts'] -and $null -ne $identityCmd.Parameters['RetryDelayMilliseconds']) 'Get-WPCTMachineIdentity exposes WMI retry parameters'

$global:Transcript = 'C:\Temp\wpct-transcript.log'
try {
    $transcriptBlocked = $false
    try {
        Assert-WPCTSafeLogging | Out-Null
    }
    catch {
        $transcriptBlocked = $true
    }
    Assert-True $transcriptBlocked 'Assert-WPCTSafeLogging blocks active PowerShell transcript'
    Assert-True (Assert-WPCTSafeLogging -AllowUnsafeLogging) 'Assert-WPCTSafeLogging allows explicit test override'
}
finally {
    Remove-Variable -Name Transcript -Scope Global -ErrorAction SilentlyContinue
}

$bstrTestSecure = ConvertTo-SecureString 'BstrMarshalSecret!' -AsPlainText -Force
$bstrTestCred = New-Object Management.Automation.PSCredential('CONTOSO\bstruser', $bstrTestSecure)
$bstrSerialized = @(ConvertTo-WPCTSerializableSecrets @(
    [pscustomobject]@{
        Id         = 'BstrSecret'
        Credential = $bstrTestCred
    }
))
Assert-True ($bstrSerialized.Count -eq 1 -and $bstrSerialized[0].Password -eq 'BstrMarshalSecret!') 'BSTR credential serialization round-trips password'
$bstrSerialized[0] | Add-Member -NotePropertyName 'SecurePassword' -NotePropertyValue $bstrTestSecure -Force
$bstrSerialized[0] | Add-Member -NotePropertyName 'Credential' -NotePropertyValue $bstrTestCred -Force
Clear-WPCTPayloadSecrets -Payload $bstrSerialized
Assert-True ($null -eq $bstrSerialized[0].Password -and $null -eq $bstrSerialized[0].SecurePassword -and $null -eq $bstrSerialized[0].Credential) 'Clear-WPCTPayloadSecrets scrubs Password, SecurePassword, and Credential'

$validRegistrySubKey = Resolve-WPCTRegistrySubKey 'Company\CredentialTransfer'
Assert-True (
    $validRegistrySubKey -eq 'Company\CredentialTransfer'
) 'Safe relative registry subkey accepted'

foreach ($unsafeRegistrySubKey in @(
        '..\SensitiveKey',
        'Company\..\SensitiveKey',
        'HKLM:\SOFTWARE\Company',
        'Company\\CredentialTransfer',
        'Company\*'
    )) {
    $unsafeRegistrySubKeyRejected = $false
    try {
        Resolve-WPCTRegistrySubKey $unsafeRegistrySubKey | Out-Null
    }
    catch {
        $unsafeRegistrySubKeyRejected = $true
    }

    Assert-True (
        $unsafeRegistrySubKeyRejected
    ) "Unsafe registry subkey rejected: $unsafeRegistrySubKey"
}

$cleanupTransferIdParameter = (Get-Command Remove-WPCTCredentialTransfer).Parameters['TransferId']
$cleanupRequiresTransferId = @(
    $cleanupTransferIdParameter.Attributes |
        Where-Object {
            $_ -is [Management.Automation.ParameterAttribute] -and
            $_.Mandatory
        }
).Count -gt 0
Assert-True $cleanupRequiresTransferId 'Cleanup requires an explicit transfer ID'

$cleanupMaximumBytesParameter = (
    Get-Command Remove-WPCTCredentialTransfer
).Parameters['MaximumPackageBytes']
Assert-True (
    $null -ne $cleanupMaximumBytesParameter
) 'Cleanup exposes the bounded package-size parameter'

$singleSecret = @(ConvertTo-WPCTSerializableSecrets @(
    [pscustomobject]@{
        Id       = 'SingleSecret'
        Type     = 'PSCredential'
        Username = 'TestUser'
        Password = 'DummyPassword'
        Credential = $null
    }
))
Assert-True ($singleSecret.Count -eq 1) 'Single credential remains countable as an array'

$validPayload = [pscustomobject]@{
    SchemaVersion = $script:WPCTDefaults.PayloadSchemaVersion
    TransferId = [guid]::NewGuid().ToString('D')
    RequiredSecretIds = @('SingleSecret')
    Secrets = $singleSecret
}
Assert-True (Test-WPCTPayload $validPayload) 'Valid transfer ID and payload requirements accepted'

$invalidTransferRejected = $false
$validPayload.TransferId = 'not-a-guid'
try {
    Test-WPCTPayload $validPayload | Out-Null
}
catch {
    $invalidTransferRejected = $true
}
Assert-True $invalidTransferRejected 'Invalid transfer ID rejected'

$validPayload.TransferId = [guid]::NewGuid().ToString('D')
$validPayload.RequiredSecretIds = @('MissingSecret')
$missingPayloadRequirementRejected = $false
try {
    Test-WPCTPayload $validPayload | Out-Null
}
catch {
    $missingPayloadRequirementRejected = $true
}
Assert-True $missingPayloadRequirementRejected 'Authenticated payload requirements enforced'

Write-Host 'ALL COMMON CRYPTOGRAPHIC TESTS PASSED' -ForegroundColor Cyan
