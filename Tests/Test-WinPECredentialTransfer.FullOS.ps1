#requires -Version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
    Runs a destructive-but-isolated full-Windows integration test.
.DESCRIPTION
    Creates a uniquely named temporary registry key under HKLM:\SOFTWARE and a
    temporary directory containing only dummy credentials. The test validates:

    - authenticated package creation and reading;
    - hardware-bound key derivation;
    - protected registry contents and ACLs;
    - wrong-machine and package-tampering rejection;
    - DPAPI-protected CLIXML export and import;
    - normal transfer cleanup.

    A finally block removes the test registry key and directory even if an
    assertion fails.
#>

[CmdletBinding()]
param(
    [switch]$NoPause
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'WinPECredentialTransfer.ps1')

function Assert-WPCTTest {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if (-not $Condition) {
        throw "FAILED: $Message"
    }

    Write-Host "[PASS] $Message" -ForegroundColor Green
}

function Wait-WPCTTestCheckpoint {
    param(
        [Parameter(Mandatory = $true)][string]$Step,
        [string[]]$Details = @()
    )

    Write-Host ''
    Write-Host "========== CHECKPOINT: $Step ==========" -ForegroundColor Yellow
    foreach ($detail in $Details) {
        Write-Host $detail -ForegroundColor DarkCyan
    }

    if ($NoPause) {
        Write-Host 'Continuing automatically because -NoPause was specified.' -ForegroundColor DarkGray
        return
    }

    Read-Host 'Inspect the locations above, then press Enter to continue' | Out-Null
}

function Test-WPCTRegistryAcl {
    param([Parameter(Mandatory = $true)][string]$RegistryPath)

    $acl = Get-Acl -Path $RegistryPath -ErrorAction Stop
    $accessRules = @(
        $acl.GetAccessRules(
            $true,
            $true,
            [Security.Principal.SecurityIdentifier]
        )
    )
    $allowedSids = @('S-1-5-18', 'S-1-5-32-544')
    $actualSids = @(
        $accessRules |
            ForEach-Object { $_.IdentityReference.Value } |
            Sort-Object -Unique
    )

    $hasOnlyExpectedPrincipals =
        $actualSids.Count -eq $allowedSids.Count -and
        @($actualSids | Where-Object { $_ -notin $allowedSids }).Count -eq 0

    $fullControlForEachPrincipal = @(
        $accessRules | Where-Object {
            $sid = $_.IdentityReference.Value
            $sid -in $allowedSids -and
            $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            (
                $_.RegistryRights -band
                [Security.AccessControl.RegistryRights]::FullControl
            ) -eq [Security.AccessControl.RegistryRights]::FullControl
        }
    ).Count -eq 2

    $isValid = $acl.AreAccessRulesProtected -and
        $hasOnlyExpectedPrincipals -and
        $fullControlForEachPrincipal

    if (-not $isValid) {
        Write-Warning "Registry ACL verification failed for: $RegistryPath"
        Write-Warning "Inheritance protected: $($acl.AreAccessRulesProtected)"
        foreach ($rule in $accessRules) {
            Write-Warning (
                'ACE: SID={0}; Type={1}; Rights={2}; Inherited={3}' -f
                $rule.IdentityReference.Value,
                $rule.AccessControlType,
                $rule.RegistryRights,
                $rule.IsInherited
            )
        }
    }

    return $isValid
}

$testId = [guid]::NewGuid().ToString('N')
$registrySubKey = "WinPECredentialTransfer\Tests\$testId"
$registryPath = Join-Path 'HKLM:\SOFTWARE' $registrySubKey
$testRoot = Join-Path ([IO.Path]::GetTempPath()) "WPCT-FullOS-$testId"
$packagePath = Join-Path $testRoot 'transfer.bin'
$outputDirectory = Join-Path $testRoot 'credentials'

$username = 'WPCT-DummyUser'
$password = "Dummy-$testId"
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object Management.Automation.PSCredential($username, $securePassword)
$machineIdentity = Get-WPCTMachineIdentity
[byte[]]$originalPackage = $null
$importedCredential = $null

try {
    Write-Host "Temporary directory: $testRoot"
    Write-Host "Temporary registry key: $registryPath"

    Wait-WPCTTestCheckpoint -Step 'Test locations selected' -Details @(
        "Filesystem root: $testRoot",
        "Package path:    $packagePath",
        "CLIXML folder:   $outputDirectory",
        "Registry path:   $registryPath",
        '',
        'Nothing has been created yet.'
    )

    $createResult = New-WPCTCredentialTransfer `
        -Secrets @([pscustomobject]@{
            Id         = 'IntegrationTest'
            Credential = $credential
        }) `
        -SecretFilePath $packagePath `
        -OfflineRegistryRoot 'HKLM:\SOFTWARE' `
        -RegistrySubKey $registrySubKey `
        -RequiredSecretIds @('IntegrationTest') `
        -Metadata ([pscustomobject]@{ TestId = $testId }) `
        -MachineIdentity $machineIdentity

    Assert-WPCTTest $createResult.Success "Credential transfer created: $($createResult.Error)"
    Assert-WPCTTest (Test-Path -LiteralPath $packagePath -PathType Leaf) 'Encrypted package exists'
    Assert-WPCTTest (Test-Path -Path $registryPath) 'Bootstrap registry key exists'
    Assert-WPCTTest (Test-WPCTRegistryAcl $registryPath) 'Registry ACL allows only SYSTEM and Administrators'
    Assert-WPCTTest (-not [string]::IsNullOrWhiteSpace($createResult.Payload.TransferId)) 'Creation returns a transfer ID'
    Assert-WPCTTest ($createResult.Payload.EngineVersion -eq $script:WPCTEngineVersion) 'Creation returns the engine version'
    Assert-WPCTTest (
        $createResult.Payload.Committed -and $createResult.Payload.CleanupComplete
    ) 'Creation commits with no retained transaction artifacts'

    $registryData = Get-ItemProperty -Path $registryPath -ErrorAction Stop
    $propertyNames = @($registryData.PSObject.Properties.Name)
    Assert-WPCTTest ($propertyNames -contains 'RandomSecret') 'Registry contains the random bootstrap secret'
    Assert-WPCTTest ($propertyNames -contains 'BindingFields') 'Registry contains binding-field names'
    Assert-WPCTTest ($propertyNames -contains 'SchemaVersion') 'Registry contains the schema version'
    Assert-WPCTTest ($propertyNames -contains 'TransferId') 'Registry contains the ownership marker'
    Assert-WPCTTest ($propertyNames -contains 'EngineVersion') 'Registry contains the engine version'
    Assert-WPCTTest (
        [string]$registryData.TransferId -eq [string]$createResult.Payload.TransferId
    ) 'Registry ownership marker matches the created package'

    $collisionResult = New-WPCTCredentialTransfer `
        -Secrets @([pscustomobject]@{
            Id         = 'IntegrationTest'
            Credential = $credential
        }) `
        -SecretFilePath $packagePath `
        -OfflineRegistryRoot 'HKLM:\SOFTWARE' `
        -RegistrySubKey $registrySubKey `
        -MachineIdentity $machineIdentity

    Assert-WPCTTest (-not $collisionResult.Success) 'Existing transfer is not overwritten by default'
    Assert-WPCTTest (Test-Path -LiteralPath $packagePath) 'Original package survives collision rejection'
    Assert-WPCTTest (Test-Path -Path $registryPath) 'Original registry key survives collision rejection'

    Set-ItemProperty `
        -Path $registryPath `
        -Name 'EngineVersion' `
        -Value 'Unowned-Test-Marker' `
        -ErrorAction Stop
    try {
        $unownedReadResult = Read-WPCTCredentialTransfer `
            -SecretFilePath $packagePath `
            -RegistrySubKey $registrySubKey `
            -MachineIdentity $machineIdentity

        Assert-WPCTTest (
            -not $unownedReadResult.Success
        ) 'Read rejects a registry key without a complete ownership marker'
        Assert-WPCTTest (
            Test-Path -LiteralPath $packagePath
        ) 'Package survives rejected read'
        Assert-WPCTTest (
            Test-Path -Path $registryPath
        ) 'Registry key survives rejected read'

        $unownedCleanupResult = Remove-WPCTCredentialTransfer `
            -SecretFilePath $packagePath `
            -RegistrySubKey $registrySubKey `
            -TransferId ([guid]$createResult.Payload.TransferId)

        Assert-WPCTTest (
            -not $unownedCleanupResult.Success
        ) 'Cleanup rejects a registry key without a complete ownership marker'
        Assert-WPCTTest (
            Test-Path -LiteralPath $packagePath
        ) 'Package survives rejected cleanup'
        Assert-WPCTTest (
            Test-Path -Path $registryPath
        ) 'Registry key survives rejected cleanup'
    }
    finally {
        Set-ItemProperty `
            -Path $registryPath `
            -Name 'EngineVersion' `
            -Value $script:WPCTEngineVersion `
            -ErrorAction Stop
    }

    $unrelatedPath = Join-Path $testRoot 'Unrelated.bin'
    [IO.File]::WriteAllBytes($unrelatedPath, [byte[]](1, 2, 3, 4))
    try {
        $unrelatedCleanupResult = Remove-WPCTCredentialTransfer `
            -SecretFilePath $unrelatedPath `
            -RegistrySubKey $registrySubKey `
            -TransferId ([guid]$createResult.Payload.TransferId)

        Assert-WPCTTest (
            -not $unrelatedCleanupResult.Success
        ) 'Cleanup rejects a file that is not the authenticated transfer package'
        Assert-WPCTTest (
            Test-Path -LiteralPath $unrelatedPath
        ) 'Unrelated file survives rejected cleanup'
        Assert-WPCTTest (
            Test-Path -LiteralPath $packagePath
        ) 'Real package survives unrelated-file cleanup rejection'
        Assert-WPCTTest (
            Test-Path -Path $registryPath
        ) 'Registry key survives unrelated-file cleanup rejection'
    }
    finally {
        Remove-Item -LiteralPath $unrelatedPath -Force -ErrorAction SilentlyContinue
    }

    $packageLock = [IO.File]::Open(
        $packagePath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $lockedCleanupResult = Remove-WPCTCredentialTransfer `
            -SecretFilePath $packagePath `
            -RegistrySubKey $registrySubKey `
            -TransferId ([guid]$createResult.Payload.TransferId)

        Assert-WPCTTest (
            -not $lockedCleanupResult.Success
        ) 'Cleanup reports a locked package deletion failure'
        Assert-WPCTTest (
            Test-Path -LiteralPath $packagePath
        ) 'Locked package survives failed cleanup'
        Assert-WPCTTest (
            Test-WPCTRegistryTransferMarker `
                -RegistryPath $registryPath `
                -TransferId ([guid]$createResult.Payload.TransferId)
        ) 'Registry ownership survives failed package cleanup'

        $lockedOverwriteResult = New-WPCTCredentialTransfer `
            -Secrets @([pscustomobject]@{
                Id         = 'IntegrationTest'
                Credential = $credential
            }) `
            -SecretFilePath $packagePath `
            -OfflineRegistryRoot 'HKLM:\SOFTWARE' `
            -RegistrySubKey $registrySubKey `
            -MachineIdentity $machineIdentity `
            -AllowOverwrite

        Assert-WPCTTest (
            -not $lockedOverwriteResult.Success
        ) 'Locked package causes overwrite to fail safely'
        Assert-WPCTTest (
            $lockedOverwriteResult.Payload.RolledBack
        ) 'Failed overwrite reports successful rollback'
        Assert-WPCTTest (
            $null -eq $lockedOverwriteResult.Payload.PackageBackupPath -and
            $null -eq $lockedOverwriteResult.Payload.RegistryBackupPath -and
            $null -eq $lockedOverwriteResult.Payload.RegistryStagePath -and
            $null -eq $lockedOverwriteResult.Payload.TemporaryPackagePath
        ) 'Failed overwrite leaves no transaction artifacts'
        Assert-WPCTTest (
            Test-Path -LiteralPath $packagePath
        ) 'Original package survives failed overwrite'
        Assert-WPCTTest (
            Test-WPCTRegistryTransferMarker `
                -RegistryPath $registryPath `
                -TransferId ([guid]$createResult.Payload.TransferId)
        ) 'Original registry ownership survives failed overwrite'
    }
    finally {
        $packageLock.Dispose()
    }

    $previousTransferId = [guid]$createResult.Payload.TransferId
    $successfulOverwriteResult = New-WPCTCredentialTransfer `
        -Secrets @([pscustomobject]@{
            Id         = 'IntegrationTest'
            Credential = $credential
        }) `
        -SecretFilePath $packagePath `
        -OfflineRegistryRoot 'HKLM:\SOFTWARE' `
        -RegistrySubKey $registrySubKey `
        -RequiredSecretIds @('IntegrationTest') `
        -Metadata ([pscustomobject]@{ TestId = $testId; Operation = 'Overwrite' }) `
        -MachineIdentity $machineIdentity `
        -AllowOverwrite

    Assert-WPCTTest (
        $successfulOverwriteResult.Success
    ) "Existing transfer is replaced transactionally: $($successfulOverwriteResult.Error)"
    $replacementTransferId = [guid]$successfulOverwriteResult.Payload.TransferId
    Assert-WPCTTest (
        $replacementTransferId -ne $previousTransferId
    ) 'Successful overwrite creates a new transfer ID'
    Assert-WPCTTest (
        @($successfulOverwriteResult.Payload.Warnings).Count -eq 0
    ) 'Successful overwrite removes all previous transaction backups'
    Assert-WPCTTest (
        $successfulOverwriteResult.Payload.Committed -and
        $successfulOverwriteResult.Payload.CleanupComplete
    ) 'Successful overwrite reports a complete transaction'
    Assert-WPCTTest (
        Test-WPCTRegistryTransferMarker `
            -RegistryPath $registryPath `
            -TransferId $replacementTransferId
    ) 'Replacement registry ownership marker is valid'
    Assert-WPCTTest (
        Test-WPCTRegistryAcl $registryPath
    ) 'Replacement registry ACL allows only SYSTEM and Administrators'

    $replacementReadResult = Read-WPCTCredentialTransfer `
        -SecretFilePath $packagePath `
        -RegistrySubKey $registrySubKey `
        -RequiredSecretIds @('IntegrationTest') `
        -MachineIdentity $machineIdentity
    Assert-WPCTTest (
        $replacementReadResult.Success
    ) "Replacement package authenticates successfully: $($replacementReadResult.Error)"
    Assert-WPCTTest (
        [guid]$replacementReadResult.Payload.TransferId -eq $replacementTransferId
    ) 'Replacement package and registry transfer IDs match'
    foreach ($secret in @($replacementReadResult.Payload.Secrets)) {
        $secret.Password = $null
    }

    $replacementSuffix = $replacementTransferId.ToString('N')
    $packageBackupPath = '{0}.{1}.bak' -f $packagePath, $replacementSuffix
    $registryBackupPath = '{0}.wpct-backup-{1}' -f $registryPath, $replacementSuffix
    Assert-WPCTTest (
        -not (Test-Path -LiteralPath $packageBackupPath)
    ) 'Successful overwrite leaves no package backup'
    Assert-WPCTTest (
        -not (Test-Path -Path $registryBackupPath)
    ) 'Successful overwrite leaves no registry backup'

    $createResult = $successfulOverwriteResult
    $registryText = $registryData | Out-String
    Assert-WPCTTest ($registryText -notmatch [regex]::Escape($username)) 'Registry does not contain the username'
    Assert-WPCTTest ($registryText -notmatch [regex]::Escape($password)) 'Registry does not contain the password'

    Wait-WPCTTestCheckpoint -Step 'Encrypted transfer created' -Details @(
        "Encrypted package: $packagePath",
        "Registry key:      $registryPath",
        '',
        'Inspect the package:',
        "  Get-Item -LiteralPath '$packagePath' | Format-List FullName,Length,CreationTimeUtc",
        '',
        'Inspect registry values:',
        "  Get-ItemProperty -Path '$registryPath' | Format-List",
        '',
        'Inspect registry ACLs:',
        "  Get-Acl -Path '$registryPath' | Format-List Owner,AreAccessRulesProtected,Access"
    )

    $wrongIdentity = [pscustomobject]@{
        SmbiosUuid   = $machineIdentity.SmbiosUuid
        SerialNumber = $machineIdentity.SerialNumber
        BindingFields = @($machineIdentity.BindingFields)
    }

    if ($wrongIdentity.BindingFields -contains 'SmbiosUuid') {
        $wrongIdentity.SmbiosUuid = '11111111-1111-1111-1111-111111111111'
    }
    elseif ($wrongIdentity.BindingFields -contains 'SerialNumber') {
        $wrongIdentity.SerialNumber = 'WPCT-WRONG-SERIAL'
    }

    if ($wrongIdentity.BindingFields.Count -gt 0) {
        $wrongMachineResult = Read-WPCTCredentialTransfer `
            -SecretFilePath $packagePath `
            -RegistrySubKey $registrySubKey `
            -RequiredSecretIds @('IntegrationTest') `
            -MachineIdentity $wrongIdentity

        Assert-WPCTTest (-not $wrongMachineResult.Success) 'Wrong machine identity is rejected'

        Wait-WPCTTestCheckpoint -Step 'Wrong-machine test completed' -Details @(
            'The original package and registry key are still present and unchanged.',
            "Package path:  $packagePath",
            "Registry path: $registryPath",
            "Expected rejection: $($wrongMachineResult.Error)"
        )
    }
    else {
        Write-Warning 'No usable UUID or serial is available; wrong-machine rejection cannot be tested.'
    }

    $originalPackage = [IO.File]::ReadAllBytes($packagePath)
    [byte[]]$tamperedPackage = New-Object byte[] $originalPackage.Length
    [Array]::Copy($originalPackage, $tamperedPackage, $originalPackage.Length)
    $tamperedPackage[$tamperedPackage.Length - 1] =
        $tamperedPackage[$tamperedPackage.Length - 1] -bxor 1

    try {
        [IO.File]::WriteAllBytes($packagePath, $tamperedPackage)
        $tamperedResult = Read-WPCTCredentialTransfer `
            -SecretFilePath $packagePath `
            -RegistrySubKey $registrySubKey `
            -RequiredSecretIds @('IntegrationTest') `
            -MachineIdentity $machineIdentity

        Assert-WPCTTest (-not $tamperedResult.Success) 'Modified package is rejected'

        Wait-WPCTTestCheckpoint -Step 'Tampered package rejected' -Details @(
            "Package path: $packagePath",
            'The file is intentionally modified at this checkpoint.',
            'Do not attempt the real import until the test restores it.',
            "Expected rejection: $($tamperedResult.Error)"
        )
    }
    finally {
        [IO.File]::WriteAllBytes($packagePath, $originalPackage)
        Clear-WPCTByteArray $tamperedPackage
    }

    $rollbackDirectory = Join-Path $testRoot 'RollbackCredentials'
    New-Item -ItemType Directory -Path $rollbackDirectory -Force -ErrorAction Stop | Out-Null
    $firstExistingPath = Join-Path $rollbackDirectory 'First.xml'
    $secondExistingPath = Join-Path $rollbackDirectory 'Second.xml'
    [IO.File]::WriteAllText($firstExistingPath, 'ORIGINAL-FIRST')
    [IO.File]::WriteAllText($secondExistingPath, 'ORIGINAL-SECOND')

    $secondFileLock = [IO.File]::Open(
        $secondExistingPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $rollbackPayload = [pscustomobject]@{
            Secrets = @(
                [pscustomobject]@{
                    Id       = 'First'
                    Type     = 'PSCredential'
                    Username = 'RollbackFirst'
                    Password = 'RollbackPassword1!'
                },
                [pscustomobject]@{
                    Id       = 'Second'
                    Type     = 'PSCredential'
                    Username = 'RollbackSecond'
                    Password = 'RollbackPassword2!'
                }
            )
        }

        $rollbackResult = Export-WPCTCredentialClixml `
            -Payload $rollbackPayload `
            -OutputDirectory $rollbackDirectory `
            -AllowOverwrite

        Assert-WPCTTest (
            -not $rollbackResult.Success
        ) 'Locked destination forces transactional CLIXML export failure'
        Assert-WPCTTest (
            $rollbackResult.Payload.RolledBack
        ) 'CLIXML export reports successful rollback'
        Assert-WPCTTest (
            -not $rollbackResult.Payload.Committed
        ) 'Failed CLIXML export reports that commit did not complete'
        Assert-WPCTTest (
            [IO.File]::ReadAllText($firstExistingPath) -eq 'ORIGINAL-FIRST'
        ) 'First existing credential file is restored after rollback'
        Assert-WPCTTest (
            [IO.File]::ReadAllText($secondExistingPath) -eq 'ORIGINAL-SECOND'
        ) 'Locked existing credential file remains unchanged'
        Assert-WPCTTest (
            $null -eq $rollbackResult.Payload.BackupDirectory
        ) 'Successful rollback leaves no recovery backup directory'
        Assert-WPCTTest (
            $null -eq $rollbackResult.Payload.StagingDirectory -and
            @($rollbackResult.Payload.RollbackErrors).Count -eq 0
        ) 'Successful rollback leaves no staging directory or rollback errors'
    }
    finally {
        $secondFileLock.Dispose()
        $rollbackPayload = $null
    }

    Wait-WPCTTestCheckpoint -Step 'Original package restored' -Details @(
        "Restored package: $packagePath",
        "Registry key:     $registryPath",
        'The next step decrypts the package, exports CLIXML, and removes the transfer.'
    )

    $importResult = Invoke-WPCTCredentialImport `
        -SecretFilePath $packagePath `
        -OutputDirectory $outputDirectory `
        -RegistrySubKey $registrySubKey `
        -RequiredSecretIds @('IntegrationTest')

    Assert-WPCTTest $importResult.Success "Credential import completed: $($importResult.Error)"
    Assert-WPCTTest $importResult.Payload.CleanedUp 'Import reports that the transfer was cleaned up'
    Assert-WPCTTest (-not (Test-Path -LiteralPath $packagePath)) 'Encrypted package was removed'
    Assert-WPCTTest (-not (Test-Path -Path $registryPath)) 'Bootstrap registry key was removed'

    Wait-WPCTTestCheckpoint -Step 'Import and transfer cleanup completed' -Details @(
        "Removed package:      $packagePath",
        "Removed registry key: $registryPath",
        "CLIXML directory:     $outputDirectory",
        '',
        'Inspect exported files:',
        "  Get-ChildItem -LiteralPath '$outputDirectory' | Format-List FullName,Length,CreationTimeUtc"
    )

    $clixmlPath = Join-Path $outputDirectory 'IntegrationTest.xml'
    Assert-WPCTTest (Test-Path -LiteralPath $clixmlPath -PathType Leaf) 'DPAPI-protected CLIXML exists'

    $importedCredential = Import-Clixml -LiteralPath $clixmlPath -ErrorAction Stop
    Assert-WPCTTest ($importedCredential -is [Management.Automation.PSCredential]) 'CLIXML imports as a PSCredential'
    Assert-WPCTTest ($importedCredential.UserName -eq $username) 'Imported username matches'
    Assert-WPCTTest ($importedCredential.GetNetworkCredential().Password -eq $password) 'Imported password matches'

    Wait-WPCTTestCheckpoint -Step 'DPAPI credential validated' -Details @(
        "CLIXML file: $clixmlPath",
        "DPAPI owner: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)",
        '',
        'The dummy password is deliberately not displayed.',
        'After you continue, the final cleanup block removes the entire test directory.'
    )

    Write-Host 'ALL FULL-OS INTEGRATION TESTS PASSED' -ForegroundColor Cyan
}
finally {
    Clear-WPCTByteArray $originalPackage
    $securePassword = $null
    $credential = $null
    $importedCredential = $null

    Remove-Item -Path $registryPath -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host ''
    Write-Host '========== FINAL CLEANUP ==========' -ForegroundColor Yellow
    Write-Host "Registry key removed: $registryPath" -ForegroundColor DarkCyan
    Write-Host "Test directory removed: $testRoot" -ForegroundColor DarkCyan

    if (Test-Path -Path $registryPath) {
        Write-Warning "Manual registry cleanup required: $registryPath"
    }
    if (Test-Path -LiteralPath $testRoot) {
        Write-Warning "Manual directory cleanup required: $testRoot"
    }
}
