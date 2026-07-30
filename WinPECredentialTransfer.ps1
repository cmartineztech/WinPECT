#requires -Version 5.1
<#
.SYNOPSIS
    Securely transfers credentials from WinPE to the installed Windows system.
.DESCRIPTION
    Moves temporary deployment credentials from Windows PE into the installed
    Windows system without placing usable passwords in scripts or answer files.

    In Windows PE, the engine creates an encrypted package on the target drive
    and stores its separate bootstrap secret in the offline SOFTWARE registry
    hive. After Windows starts, it verifies and decrypts the package, exports
    each credential as a DPAPI-protected CLIXML file for the current identity,
    and removes the temporary transfer artifacts.

    The package and registry secret are both required. Available hardware
    identifiers can also bind the transfer to the target computer. File and
    registry ACLs, authenticated ownership checks, size limits, and recoverable
    transactions protect creation, import, overwrite, and cleanup.
.EXAMPLE
    . .\WinPECredentialTransfer.ps1

    Loads the engine functions into the current Windows PowerShell 5.1 session.
.EXAMPLE
    $mount = Mount-WPCTOfflineSoftwareHive -WindowsPath 'C:\Windows'
    if (-not $mount.Success) { throw $mount.Error }

    try {
        $result = New-WPCTCredentialTransfer `
            -Secrets @([pscustomobject]@{
                Id = 'DeploymentShare'
                Credential = Get-Credential
            }) `
            -SecretFilePath 'C:\Deployment\Credentials.bin' `
            -OfflineRegistryRoot $mount.Payload.RegistryRoot `
            -RegistrySubKey 'Company\DeploymentBootstrap' `
            -RequiredSecretIds @('DeploymentShare')

        if (-not $result.Success) { throw $result.Error }
    }
    finally {
        Dismount-WPCTOfflineSoftwareHive `
            -MountName $mount.Payload.MountName | Out-Null
    }

    Creates a protected transfer while running in WinPE.
.EXAMPLE
    $result = Invoke-WPCTCredentialImport `
        -SecretFilePath 'C:\Deployment\Credentials.bin' `
        -OutputDirectory 'C:\ProgramData\Company\Credentials' `
        -RegistrySubKey 'Company\DeploymentBootstrap' `
        -RequiredSecretIds @('DeploymentShare')

    if (-not $result.Success) { throw $result.Error }
    $result.Payload.ClixmlFiles

    Imports the transfer in full Windows, creates DPAPI-protected CLIXML, and
    removes the binary package and bootstrap registry key.
#>

param()

Set-StrictMode -Version 2.0

$script:WPCTEngineVersion = '3.0.0'
$script:WPCTDefaults = [pscustomobject]@{
    RegistrySubKey         = 'WinPECredentialTransfer\Bootstrap'
    RandomSecretValueName = 'RandomSecret'
    BindingFieldsValueName = 'BindingFields'
    SchemaVersionValueName = 'SchemaVersion'
    TransferIdValueName     = 'TransferId'
    EngineVersionValueName = 'EngineVersion'
    MaximumPackageBytes    = 10MB
    PackageVersion         = 3
    PayloadSchemaVersion   = 4
    RegistrySchemaVersion  = 4
}

#region Common helpers

function New-WPCTResult {
    param(
        [Parameter(Mandatory=$true)][bool]$Success,
        [object]$Payload=$null,
        [string]$ErrorMessage=$null
    )
    [pscustomobject]@{
        Success = $Success
        Payload = $Payload
        Error   = $ErrorMessage
    }
}

function Resolve-WPCTRegistrySubKey {
    param([string]$RegistrySubKey = $script:WPCTDefaults.RegistrySubKey)

    $value = $RegistrySubKey.Trim().TrimStart('\').TrimEnd('\')
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw 'RegistrySubKey cannot be empty.'
    }

    if ($value.IndexOfAny([char[]]@('/', ':', '*', '?', '[', ']')) -ge 0) {
        throw 'RegistrySubKey contains unsupported path or wildcard characters.'
    }

    foreach ($segment in $value.Split('\')) {
        $containsControlCharacter = $false
        foreach ($character in $segment.ToCharArray()) {
            if ([char]::IsControl($character)) {
                $containsControlCharacter = $true
                break
            }
        }

        if (
            [string]::IsNullOrWhiteSpace($segment) -or
            $segment -eq '.' -or
            $segment -eq '..' -or
            $containsControlCharacter
        ) {
            throw 'RegistrySubKey must contain only nonempty relative key names.'
        }
    }

    return $value
}

function Assert-WPCTPathHasNoReparsePoint {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LiteralPath
    )

    $fullPath = [IO.Path]::GetFullPath($LiteralPath)
    $currentPath = $fullPath

    while (-not [string]::IsNullOrWhiteSpace($currentPath)) {
        if (Test-Path -LiteralPath $currentPath) {
            $item = Get-Item -LiteralPath $currentPath -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Path must not contain a reparse point: $currentPath"
            }
        }

        $parentPath = Split-Path -Parent $currentPath
        if ([string]::IsNullOrWhiteSpace($parentPath) -or $parentPath -eq $currentPath) {
            break
        }
        $currentPath = $parentPath
    }

    return $fullPath
}

function Read-WPCTBoundedFile {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LiteralPath,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 104857600)]
        [int64]$MaximumBytes
    )

    $stream = $null
    [byte[]]$bytes = $null

    try {
        $stream = New-Object IO.FileStream(
            $LiteralPath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )

        if ($stream.Length -gt $MaximumBytes) {
            throw "Secret package exceeds the $MaximumBytes byte limit."
        }
        if ($stream.Length -gt [int]::MaxValue) {
            throw 'Secret package is too large to read safely.'
        }

        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -eq 0) {
                throw 'Secret package ended before the expected number of bytes was read.'
            }
            $offset += $read
        }

        return $bytes
    }
    catch {
        Clear-WPCTByteArray $bytes
        throw
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

function Clear-WPCTByteArray {
    param([byte[]]$Bytes)

    if ($null -ne $Bytes) {
        [Array]::Clear($Bytes, 0, $Bytes.Length)
    }
}

function Test-WPCTRegistryOwnership {
    param(
        [Parameter(Mandatory = $true)][string]$RegistryPath,
        [Parameter(Mandatory = $true)][guid]$TransferId
    )

    if (-not (Test-Path -Path $RegistryPath)) {
        return $false
    }

    try {
        $data = Get-ItemProperty -Path $RegistryPath -ErrorAction Stop
        return [string]$data.($script:WPCTDefaults.TransferIdValueName) -eq $TransferId.ToString('D')
    }
    catch {
        return $false
    }
}

function Test-WPCTRegistryTransferMarker {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RegistryPath,

        [Parameter(Mandatory = $true)]
        [guid]$TransferId
    )

    if (-not (Test-Path -Path $RegistryPath)) {
        return $false
    }

    try {
        $data = Get-ItemProperty -Path $RegistryPath -ErrorAction Stop
        $storedTransferId = [guid]::Empty
        $hasValidTransferId = [guid]::TryParse(
            [string]$data.($script:WPCTDefaults.TransferIdValueName),
            [ref]$storedTransferId
        )

        return (
            $hasValidTransferId -and
            $storedTransferId -eq $TransferId -and
            [int]$data.($script:WPCTDefaults.SchemaVersionValueName) -eq
                $script:WPCTDefaults.RegistrySchemaVersion -and
            [string]$data.($script:WPCTDefaults.EngineVersionValueName) -eq
                $script:WPCTEngineVersion
        )
    }
    catch {
        return $false
    }
}

function New-WPCTRandomBytes {
    param([Parameter(Mandatory=$true)][ValidateRange(1,4096)][int]$Length)
    [byte[]]$bytes = New-Object byte[] $Length
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()

    try {
        $rng.GetBytes($bytes)
        return $bytes
    }
    finally {
        $rng.Dispose()
    }
}

function Test-WPCTFixedTimeEquals {
    param([Parameter(Mandatory=$true)][byte[]]$Left,[Parameter(Mandatory=$true)][byte[]]$Right)
    if ($Left.Length -ne $Right.Length) {
        return $false
    }

    [int]$difference = 0
    for ($i = 0; $i -lt $Left.Length; $i++) {
        $difference = $difference -bor ($Left[$i] -bxor $Right[$i])
    }

    return ($difference -eq 0)
}

#endregion Common helpers

#region Hardware identity and key derivation

function ConvertTo-WPCTNormalizedHardwareValue {
    [CmdletBinding()]
    param([AllowNull()][object]$Value,[Parameter(Mandatory=$true)][ValidateSet('SmbiosUuid','SerialNumber')][string]$Type)
    if($null-eq $Value){return $null}
    $v=([string]$Value).Trim().ToUpperInvariant()
    if([string]::IsNullOrWhiteSpace($v)){return $null}
    $invalid=@('UNKNOWN','NONE','N/A','NA','NULL','DEFAULT STRING','TO BE FILLED BY O.E.M.','TO BE FILLED BY OEM','SYSTEM SERIAL NUMBER','NO SERIAL NUMBER','NOT SPECIFIED','NOT AVAILABLE')
    if($invalid-contains $v){return $null}
    if($Type-eq 'SmbiosUuid'){
        if($v-eq '00000000-0000-0000-0000-000000000000'-or$v-eq 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF'){return $null}
        [guid]$g=[guid]::Empty
        if(-not [guid]::TryParse($v,[ref]$g)){return $null}
        return $g.ToString('D').ToUpperInvariant()
    }
    return $v
}

function Get-WPCTMachineIdentity {
    [CmdletBinding()]
    param()

    $serial = $null
    $uuid = $null

    try {
        $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop | Select-Object -First 1
        $serial = ConvertTo-WPCTNormalizedHardwareValue -Value $bios.SerialNumber -Type SerialNumber
    }
    catch {
        Write-Verbose "BIOS serial number is unavailable: $($_.Exception.Message)"
    }

    try {
        $systemProduct = Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop |
            Select-Object -First 1
        $uuid = ConvertTo-WPCTNormalizedHardwareValue -Value $systemProduct.UUID -Type SmbiosUuid
    }
    catch {
        Write-Verbose "SMBIOS UUID is unavailable: $($_.Exception.Message)"
    }

    $fields = New-Object System.Collections.Generic.List[string]
    if ($null -ne $uuid) {
        $fields.Add('SmbiosUuid')
    }
    if ($null -ne $serial) {
        $fields.Add('SerialNumber')
    }

    [pscustomobject]@{
        SmbiosUuid   = $uuid
        SerialNumber = $serial
        BindingFields = $fields.ToArray()
    }
}

function Get-WPCTBindingContextBytes {
    param(
        [Parameter(Mandatory = $true)]$MachineIdentity,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$BindingFields
    )
    $parts=New-Object System.Collections.Generic.List[string];$parts.Add('WPCT-HARDWARE-BINDING-V3')
    foreach($field in $BindingFields){
        switch($field){
            'SmbiosUuid'{$value=ConvertTo-WPCTNormalizedHardwareValue -Value $MachineIdentity.SmbiosUuid -Type SmbiosUuid}
            'SerialNumber'{$value=ConvertTo-WPCTNormalizedHardwareValue -Value $MachineIdentity.SerialNumber -Type SerialNumber}
            default{throw "Unsupported binding field: $field"}
        }
        if($null-eq $value){throw "Binding field '$field' was selected in WinPE but is unavailable now."}
        $parts.Add(('{0}:{1}:{2}'-f$field,$value.Length,$value))
    }
    [Text.Encoding]::UTF8.GetBytes(($parts-join '|'))
}

function Invoke-WPCTHmacSha256 {
    param([Parameter(Mandatory=$true)][byte[]]$Key,[Parameter(Mandatory=$true)][byte[]]$Data)
    $h=New-Object Security.Cryptography.HMACSHA256
    try{$h.Key=$Key;return $h.ComputeHash($Data)}finally{$h.Dispose()}
}

#endregion Hardware identity and key derivation

#region Package encryption

function Invoke-WPCTHkdfSha256 {
    param([Parameter(Mandatory=$true)][byte[]]$InputKeyMaterial,[Parameter(Mandatory=$true)][byte[]]$Salt,[Parameter(Mandatory=$true)][byte[]]$Info,[Parameter(Mandatory=$true)][ValidateRange(1,8160)][int]$Length)
    [byte[]]$prk=$null;[byte[]]$previous=New-Object byte[] 0;[byte[]]$output=New-Object byte[] $Length
    try{
        $prk=Invoke-WPCTHmacSha256 -Key $Salt -Data $InputKeyMaterial
        $offset=0;$blocks=[Math]::Ceiling($Length/32.0)
        for($counter=1;$counter-le $blocks;$counter++){
            [byte[]]$hmacInput = New-Object byte[] ($previous.Length + $Info.Length + 1)
            try{
                if($previous.Length-gt 0){[Array]::Copy($previous,0,$hmacInput,0,$previous.Length)}
                [Array]::Copy($Info,0,$hmacInput,$previous.Length,$Info.Length);$hmacInput[$hmacInput.Length-1]=[byte]$counter
                Clear-WPCTByteArray $previous;$previous=Invoke-WPCTHmacSha256 -Key $prk -Data $hmacInput
                $copy=[Math]::Min(32,$Length-$offset);[Array]::Copy($previous,0,$output,$offset,$copy);$offset+=$copy
            }finally{Clear-WPCTByteArray $hmacInput}
        }
        return $output
    }finally{Clear-WPCTByteArray $prk;Clear-WPCTByteArray $previous}
}

function New-WPCTDerivedKeys {
    param(
        [Parameter(Mandatory = $true)][byte[]]$RandomSecret,
        [Parameter(Mandatory = $true)]$MachineIdentity,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$BindingFields
    )
    [byte[]]$salt=$null;[byte[]]$info=$null;[byte[]]$derived=$null
    [byte[]]$enc=New-Object byte[] 32;[byte[]]$mac=New-Object byte[] 32
    try{
        $sha=[Security.Cryptography.SHA256]::Create()
        try{$salt=$sha.ComputeHash([Text.Encoding]::UTF8.GetBytes('WinPE Credential Transfer|HKDF|v3'))}finally{$sha.Dispose()}
        $info=Get-WPCTBindingContextBytes -MachineIdentity $MachineIdentity -BindingFields $BindingFields
        $derived=Invoke-WPCTHkdfSha256 -InputKeyMaterial $RandomSecret -Salt $salt -Info $info -Length 64
        [Array]::Copy($derived,0,$enc,0,32);[Array]::Copy($derived,32,$mac,0,32)
        [pscustomobject]@{EncryptionKey=$enc;MacKey=$mac}
    }catch{Clear-WPCTByteArray $enc;Clear-WPCTByteArray $mac;throw}finally{Clear-WPCTByteArray $salt;Clear-WPCTByteArray $info;Clear-WPCTByteArray $derived}
}

function Protect-WPCTBytes {
    param([Parameter(Mandatory=$true)][byte[]]$PlainBytes,[Parameter(Mandatory=$true)][byte[]]$EncryptionKey,[Parameter(Mandatory=$true)][byte[]]$MacKey)
    [byte[]]$iv=New-WPCTRandomBytes 16;[byte[]]$cipher=$null;[byte[]]$signed=$null;[byte[]]$tag=$null
    try{
        $aes=New-Object Security.Cryptography.AesCryptoServiceProvider;$aes.KeySize=256;$aes.BlockSize=128;$aes.Mode='CBC';$aes.Padding='PKCS7';$aes.Key=$EncryptionKey;$aes.IV=$iv
        try{$e=$aes.CreateEncryptor();try{$cipher=$e.TransformFinalBlock($PlainBytes,0,$PlainBytes.Length)}finally{$e.Dispose()}}finally{$aes.Dispose()}
        [byte[]]$magic=[Text.Encoding]::ASCII.GetBytes('WPCT');$signed=New-Object byte[] (21+$cipher.Length)
        [Array]::Copy($magic,0,$signed,0,4);$signed[4]=[byte]$script:WPCTDefaults.PackageVersion;[Array]::Copy($iv,0,$signed,5,16);[Array]::Copy($cipher,0,$signed,21,$cipher.Length)
        $tag=Invoke-WPCTHmacSha256 -Key $MacKey -Data $signed
        [byte[]]$package=New-Object byte[] (53+$cipher.Length)
        [Array]::Copy($magic,0,$package,0,4);$package[4]=[byte]$script:WPCTDefaults.PackageVersion;[Array]::Copy($iv,0,$package,5,16);[Array]::Copy($tag,0,$package,21,32);[Array]::Copy($cipher,0,$package,53,$cipher.Length)
        return $package
    }finally{Clear-WPCTByteArray $iv;Clear-WPCTByteArray $cipher;Clear-WPCTByteArray $signed;Clear-WPCTByteArray $tag}
}

function Unprotect-WPCTBytes {
    param([Parameter(Mandatory=$true)][byte[]]$PackageBytes,[Parameter(Mandatory=$true)][byte[]]$EncryptionKey,[Parameter(Mandatory=$true)][byte[]]$MacKey)
    if($PackageBytes.Length-lt 69){throw 'Secrets package is too small.'}
    if([Text.Encoding]::ASCII.GetString($PackageBytes,0,4)-ne 'WPCT'){throw 'Invalid package header.'}
    if($PackageBytes[4]-ne $script:WPCTDefaults.PackageVersion){throw "Unsupported package version: $($PackageBytes[4])"}
    [byte[]]$iv=New-Object byte[] 16;[byte[]]$stored=New-Object byte[] 32;[byte[]]$cipher=New-Object byte[] ($PackageBytes.Length-53);[byte[]]$signed=$null;[byte[]]$calc=$null
    try{
        [Array]::Copy($PackageBytes,5,$iv,0,16);[Array]::Copy($PackageBytes,21,$stored,0,32);[Array]::Copy($PackageBytes,53,$cipher,0,$cipher.Length)
        [byte[]]$magic=[Text.Encoding]::ASCII.GetBytes('WPCT');$signed=New-Object byte[] (21+$cipher.Length)
        [Array]::Copy($magic,0,$signed,0,4);$signed[4]=[byte]$script:WPCTDefaults.PackageVersion;[Array]::Copy($iv,0,$signed,5,16);[Array]::Copy($cipher,0,$signed,21,$cipher.Length)
        $calc=Invoke-WPCTHmacSha256 -Key $MacKey -Data $signed
        if(-not(Test-WPCTFixedTimeEquals $stored $calc)){throw 'Package authentication failed. Random secret or hardware binding is incorrect.'}
        $aes=New-Object Security.Cryptography.AesCryptoServiceProvider;$aes.KeySize=256;$aes.BlockSize=128;$aes.Mode='CBC';$aes.Padding='PKCS7';$aes.Key=$EncryptionKey;$aes.IV=$iv
        try{$d=$aes.CreateDecryptor();try{return $d.TransformFinalBlock($cipher,0,$cipher.Length)}finally{$d.Dispose()}}finally{$aes.Dispose()}
    }finally{Clear-WPCTByteArray $iv;Clear-WPCTByteArray $stored;Clear-WPCTByteArray $cipher;Clear-WPCTByteArray $signed;Clear-WPCTByteArray $calc}
}

#endregion Package encryption

#region Payload validation

function ConvertTo-WPCTSerializableSecrets {
    param([Parameter(Mandatory=$true)][array]$Secrets)
    $out=New-Object System.Collections.Generic.List[object];$seen=@{}
    foreach($secret in $Secrets){
        $id=[string]$secret.Id;if([string]::IsNullOrWhiteSpace($id)-or$id-notmatch'^[A-Za-z0-9._-]+$'){throw "Invalid secret Id: $id"};if($seen.ContainsKey($id)){throw "Duplicate secret Id: $id"};$seen[$id]=$true
        if($null-ne $secret.Credential){
            if($secret.Credential-isnot[Management.Automation.PSCredential]){throw "Credential for '$id' is not a PSCredential."}
            $nc=$secret.Credential.GetNetworkCredential();try{$out.Add([pscustomobject]@{Id=$id;Type='PSCredential';Username=$secret.Credential.UserName;Password=$nc.Password})}finally{$nc=$null}
        }else{
            if([string]$secret.Type-ne'PSCredential'){throw "Unsupported secret type for '$id'."}
            if([string]::IsNullOrWhiteSpace([string]$secret.Username)-or$null-eq$secret.Password){throw "Username or password missing for '$id'."}
            $out.Add([pscustomobject]@{Id=$id;Type='PSCredential';Username=[string]$secret.Username;Password=[string]$secret.Password})
        }
    }
    $out.ToArray()
}

function Test-WPCTPayload {
    param(
        [Parameter(Mandatory = $true)]$Payload,
        [string[]]$RequiredSecretIds = @()
    )

    if ($null -eq $Payload -or [int]$Payload.SchemaVersion -ne $script:WPCTDefaults.PayloadSchemaVersion) {
        throw 'Invalid payload schema.'
    }
    $transferGuid = [guid]::Empty
    if (-not [guid]::TryParse([string]$Payload.TransferId, [ref]$transferGuid)) {
        throw 'Payload contains an invalid TransferId.'
    }

    $seen = @{}
    $secrets = @($Payload.Secrets)
    if ($secrets.Count -eq 0) {
        throw 'Payload contains no secrets.'
    }

    foreach ($secret in $secrets) {
        $id = [string]$secret.Id
        if ([string]::IsNullOrWhiteSpace($id) -or $id -notmatch '^[A-Za-z0-9._-]+$') {
            throw "Invalid secret Id: $id"
        }
        if ($seen.ContainsKey($id)) {
            throw "Duplicate secret Id: $id"
        }

        $seen[$id] = $true
        $invalidCredential =
            [string]$secret.Type -ne 'PSCredential' -or
            [string]::IsNullOrWhiteSpace([string]$secret.Username) -or
            $null -eq $secret.Password

        if ($invalidCredential) {
            throw "Invalid PSCredential payload for '$id'."
        }
    }

    foreach ($id in $RequiredSecretIds) {
        if (-not $seen.ContainsKey($id)) {
            throw "Required secret '$id' is missing."
        }
    }

    foreach ($id in @($Payload.RequiredSecretIds)) {
        if (-not $seen.ContainsKey([string]$id)) {
            throw "Payload-required secret '$id' is missing."
        }
    }

    $true
}

#endregion Payload validation

#region Offline registry

function Mount-WPCTOfflineSoftwareHive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$WindowsPath,
        [string]$MountName='WPCTOffline'
    )
    try {
        $hive=Join-Path $WindowsPath 'System32\Config\SOFTWARE'
        if(-not(Test-Path -LiteralPath $hive -PathType Leaf)){throw "Offline SOFTWARE hive not found: $hive"}
        & reg.exe load "HKLM\$MountName" $hive | Out-Null
        if($LASTEXITCODE-ne 0){throw "reg.exe load failed with exit code $LASTEXITCODE."}
        New-WPCTResult $true ([pscustomobject]@{MountName=$MountName;RegistryRoot="HKLM:\$MountName";HivePath=$hive})
    } catch { New-WPCTResult $false $null $_.Exception.Message }
}

function Dismount-WPCTOfflineSoftwareHive {
    [CmdletBinding()]
    param([string]$MountName='WPCTOffline')
    try {
        [gc]::Collect();[gc]::WaitForPendingFinalizers()
        & reg.exe unload "HKLM\$MountName" | Out-Null
        if($LASTEXITCODE-ne 0){throw "reg.exe unload failed with exit code $LASTEXITCODE."}
        New-WPCTResult $true
    } catch { New-WPCTResult $false $null $_.Exception.Message }
}

function Set-WPCTRegistryKeyAcl {
    <# Restricts the bootstrap key to Local SYSTEM and local Administrators. #>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$RegistryPath)

    $acl = New-Object Security.AccessControl.RegistrySecurity
    $acl.SetAccessRuleProtection($true, $false)

    $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit
    $propagate = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $full = [Security.AccessControl.RegistryRights]::FullControl

    $systemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $adminsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')

    foreach ($sid in @($systemSid, $adminsSid)) {
        $rule = New-Object Security.AccessControl.RegistryAccessRule(
            $sid,
            $full,
            $inherit,
            $propagate,
            $allow
        )
        $acl.AddAccessRule($rule)
    }

    $acl.SetOwner($adminsSid)
    Set-Acl -Path $RegistryPath -AclObject $acl -ErrorAction Stop
}

function Set-WPCTFileAcl {
    <# Restricts a file to Local SYSTEM and local Administrators. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $full = [Security.AccessControl.FileSystemRights]::FullControl
    $systemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $adminsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($systemSid, $full, $allow)))
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($adminsSid, $full, $allow)))
    $acl.SetOwner($adminsSid)
    Set-Acl -LiteralPath $LiteralPath -AclObject $acl -ErrorAction Stop
}

function Set-WPCTCredentialDirectoryAcl {
    <# Restricts CLIXML output to its creator, SYSTEM, and Administrators. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $full = [Security.AccessControl.FileSystemRights]::FullControl
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagate = [Security.AccessControl.PropagationFlags]::None
    $systemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $adminsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User

    foreach ($sid in @($systemSid, $adminsSid, $currentSid)) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $sid, $full, $inherit, $propagate, $allow
        )
        $acl.AddAccessRule($rule)
    }
    $acl.SetOwner($currentSid)
    Set-Acl -LiteralPath $LiteralPath -AclObject $acl -ErrorAction Stop
}

function New-WPCTRegistryTransferKey {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RegistryPath,

        [Parameter(Mandatory = $true)]
        [guid]$TransferId,

        [Parameter(Mandatory = $true)]
        [byte[]]$RandomSecret,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$BindingFields
    )

    if (Test-Path -Path $RegistryPath) {
        throw "Refusing to create a registry transfer key over an existing key: $RegistryPath"
    }

    New-Item -Path $RegistryPath -Force -ErrorAction Stop | Out-Null
    try {
        Set-WPCTRegistryKeyAcl -RegistryPath $RegistryPath
        New-ItemProperty `
            -Path $RegistryPath `
            -Name $script:WPCTDefaults.TransferIdValueName `
            -PropertyType String `
            -Value $TransferId.ToString('D') `
            -Force `
            -ErrorAction Stop | Out-Null
        New-ItemProperty `
            -Path $RegistryPath `
            -Name $script:WPCTDefaults.RandomSecretValueName `
            -PropertyType Binary `
            -Value $RandomSecret `
            -Force `
            -ErrorAction Stop | Out-Null
        New-ItemProperty `
            -Path $RegistryPath `
            -Name $script:WPCTDefaults.BindingFieldsValueName `
            -PropertyType MultiString `
            -Value $BindingFields `
            -Force `
            -ErrorAction Stop | Out-Null
        New-ItemProperty `
            -Path $RegistryPath `
            -Name $script:WPCTDefaults.SchemaVersionValueName `
            -PropertyType DWord `
            -Value $script:WPCTDefaults.RegistrySchemaVersion `
            -Force `
            -ErrorAction Stop | Out-Null
        New-ItemProperty `
            -Path $RegistryPath `
            -Name $script:WPCTDefaults.EngineVersionValueName `
            -PropertyType String `
            -Value $script:WPCTEngineVersion `
            -Force `
            -ErrorAction Stop | Out-Null
    }
    catch {
        $originalError = $_.Exception.Message
        $cleanupError = $null
        if (Test-Path -Path $RegistryPath) {
            try {
                Remove-Item `
                    -Path $RegistryPath `
                    -Recurse `
                    -Force `
                    -ErrorAction Stop
                if (Test-Path -Path $RegistryPath) {
                    throw "Partial registry key remains: $RegistryPath"
                }
            }
            catch {
                $cleanupError = $_.Exception.Message
            }
        }
        if ($null -ne $cleanupError) {
            throw "$originalError Registry cleanup also failed: $cleanupError"
        }
        throw $originalError
    }
}

function Get-WPCTRegistryTransferKeyData {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RegistryPath
    )

    $data = Get-ItemProperty -Path $RegistryPath -ErrorAction Stop
    $transferId = [guid]::Empty
    if (-not [guid]::TryParse(
            [string]$data.($script:WPCTDefaults.TransferIdValueName),
            [ref]$transferId
        )) {
        throw "Registry key contains an invalid TransferId: $RegistryPath"
    }

    [byte[]]$randomSecret = $data.($script:WPCTDefaults.RandomSecretValueName)
    if ($null -eq $randomSecret -or $randomSecret.Length -ne 32) {
        throw "Registry key contains an invalid RandomSecret: $RegistryPath"
    }
    if (
        [int]$data.($script:WPCTDefaults.SchemaVersionValueName) -ne
        $script:WPCTDefaults.RegistrySchemaVersion
    ) {
        throw "Registry key contains an unsupported schema: $RegistryPath"
    }
    if (
        [string]$data.($script:WPCTDefaults.EngineVersionValueName) -ne
        $script:WPCTEngineVersion
    ) {
        throw "Registry key belongs to a different engine version: $RegistryPath"
    }

    [pscustomobject]@{
        TransferId = $transferId
        RandomSecret = $randomSecret
        BindingFields = @(
            $data.($script:WPCTDefaults.BindingFieldsValueName)
        )
    }
}

function Copy-WPCTRegistryTransferKey {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,

        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )

    $sourceData = $null
    try {
        $sourceData = Get-WPCTRegistryTransferKeyData -RegistryPath $SourcePath
        New-WPCTRegistryTransferKey `
            -RegistryPath $DestinationPath `
            -TransferId $sourceData.TransferId `
            -RandomSecret $sourceData.RandomSecret `
            -BindingFields $sourceData.BindingFields

        if (-not (Test-WPCTRegistryTransferMarker `
                -RegistryPath $DestinationPath `
                -TransferId $sourceData.TransferId)) {
            throw "Copied registry ownership verification failed: $DestinationPath"
        }

        return $sourceData.TransferId
    }
    catch {
        $originalError = $_.Exception.Message
        $cleanupError = $null
        if (Test-Path -Path $DestinationPath) {
            try {
                Remove-Item `
                    -Path $DestinationPath `
                    -Recurse `
                    -Force `
                    -ErrorAction Stop
                if (Test-Path -Path $DestinationPath) {
                    throw "Copied registry key remains: $DestinationPath"
                }
            }
            catch {
                $cleanupError = $_.Exception.Message
            }
        }
        if ($null -ne $cleanupError) {
            throw "$originalError Registry cleanup also failed: $cleanupError"
        }
        throw $originalError
    }
    finally {
        if ($null -ne $sourceData) {
            Clear-WPCTByteArray $sourceData.RandomSecret
        }
    }
}

#endregion Offline registry

#region Credential transfer workflow

function New-WPCTCredentialTransfer {
    <#
    .SYNOPSIS
        Creates an encrypted credential package during WinPE.
    .PARAMETER SecretFilePath
        Exact path where the encrypted package will be written.
    .PARAMETER OfflineRegistryRoot
        Root of a mounted offline SOFTWARE hive, for example HKLM:\WPCTOffline.
    .PARAMETER RegistrySubKey
        Bootstrap subkey relative to the SOFTWARE hive.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][array]$Secrets,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$SecretFilePath,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$OfflineRegistryRoot,
        [string]$RegistrySubKey=$script:WPCTDefaults.RegistrySubKey,
        [object]$Metadata=$null,
        [string[]]$RequiredSecretIds=@(),
        [object]$MachineIdentity=$null,
        [switch]$AllowOverwrite,
        [ValidateRange(1024, 104857600)][int64]$MaximumPackageBytes=$script:WPCTDefaults.MaximumPackageBytes
    )

    [byte[]]$random = $null
    [byte[]]$plain = $null
    [byte[]]$package = $null
    $keys = $null
    $payload = $null
    $serializable = @()
    $regPath = $null
    $transferId = [guid]::NewGuid()
    $temporaryPath = $null
    $packageBackupPath = $null
    $registryStagePath = $null
    $registryBackupPath = $null
    $registryLeafName = $null
    $hadExistingPackage = $false
    $hadExistingRegistry = $false
    $packageBackedUp = $false
    $registryBackedUp = $false
    $existingRegistryRemoved = $false
    $newPackageCommitted = $false
    $commitCompleted = $false

    try {
        $RegistrySubKey = Resolve-WPCTRegistrySubKey $RegistrySubKey
        $regPath = Join-Path $OfflineRegistryRoot $RegistrySubKey
        $SecretFilePath = Assert-WPCTPathHasNoReparsePoint -LiteralPath $SecretFilePath
        $temporaryPath = '{0}.{1}.tmp' -f $SecretFilePath, $transferId.ToString('N')
        $packageBackupPath = '{0}.{1}.bak' -f $SecretFilePath, $transferId.ToString('N')

        $registryParentPath = Split-Path -Parent $regPath
        $registryLeafName = Split-Path -Leaf $regPath
        $registryStageLeaf = '{0}.wpct-stage-{1}' -f $registryLeafName, $transferId.ToString('N')
        $registryBackupLeaf = '{0}.wpct-backup-{1}' -f $registryLeafName, $transferId.ToString('N')
        $registryStagePath = Join-Path $registryParentPath $registryStageLeaf
        $registryBackupPath = Join-Path $registryParentPath $registryBackupLeaf

        $hadExistingPackage = Test-Path -LiteralPath $SecretFilePath
        $hadExistingRegistry = Test-Path -Path $regPath

        if ($hadExistingPackage -and -not $AllowOverwrite) {
            throw "Secret package already exists. Use -AllowOverwrite to replace it: $SecretFilePath"
        }
        if ($hadExistingRegistry) {
            if (-not $AllowOverwrite) {
                throw "Registry bootstrap key already exists. Use a different subkey: $regPath"
            }

            $existing = Get-ItemProperty -Path $regPath -ErrorAction Stop
            $existingId = [guid]::Empty
            $hasExistingId = [guid]::TryParse(
                    [string]$existing.($script:WPCTDefaults.TransferIdValueName),
                    [ref]$existingId
                )
            if (
                -not $hasExistingId -or
                -not (Test-WPCTRegistryTransferMarker `
                    -RegistryPath $regPath `
                    -TransferId $existingId)
            ) {
                throw "Refusing to overwrite an unowned registry key: $regPath"
            }
        }

        if (
            (Test-Path -LiteralPath $packageBackupPath) -or
            (Test-Path -Path $registryStagePath) -or
            (Test-Path -Path $registryBackupPath)
        ) {
            throw 'Transfer-specific staging or backup artifacts already exist.'
        }

        if($null-eq$MachineIdentity){$MachineIdentity=Get-WPCTMachineIdentity}
        [string[]]$fields=@($MachineIdentity.BindingFields)
        # PowerShell unwraps single-item pipeline results. Force an array so
        # SecretCount and payload serialization behave consistently for one or
        # many credentials.
        $serializable = @(ConvertTo-WPCTSerializableSecrets $Secrets)
        $payload=[ordered]@{
            SchemaVersion=$script:WPCTDefaults.PayloadSchemaVersion
            EngineVersion=$script:WPCTEngineVersion
            TransferId=$transferId.ToString('D')
            CreatedUtc=[DateTime]::UtcNow.ToString('o')
            BindingFields=$fields
            RequiredSecretIds=$RequiredSecretIds
            Metadata=$Metadata
            Secrets=$serializable
        }
        Test-WPCTPayload ([pscustomobject]$payload) $RequiredSecretIds | Out-Null

        $parent = Split-Path -Parent $SecretFilePath
        if (-not [string]::IsNullOrWhiteSpace($parent)) {
            New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
            Assert-WPCTPathHasNoReparsePoint -LiteralPath $parent | Out-Null
        }

        $plain=[Text.Encoding]::UTF8.GetBytes(($payload|ConvertTo-Json -Depth 12 -Compress))
        if ($plain.Length -gt $MaximumPackageBytes) {
            throw "Serialized payload exceeds the $MaximumPackageBytes byte limit."
        }
        $random=New-WPCTRandomBytes 32
        $keys=New-WPCTDerivedKeys $random $MachineIdentity $fields
        $package=Protect-WPCTBytes $plain $keys.EncryptionKey $keys.MacKey
        if ($package.Length -gt $MaximumPackageBytes) {
            throw "Encrypted package exceeds the $MaximumPackageBytes byte limit."
        }
        [IO.File]::WriteAllBytes($temporaryPath,$package)
        Set-WPCTFileAcl -LiteralPath $temporaryPath

        New-WPCTRegistryTransferKey `
            -RegistryPath $registryStagePath `
            -TransferId $transferId `
            -RandomSecret $random `
            -BindingFields $fields

        Assert-WPCTPathHasNoReparsePoint -LiteralPath $SecretFilePath | Out-Null
        if ($hadExistingPackage) {
            Move-Item `
                -LiteralPath $SecretFilePath `
                -Destination $packageBackupPath `
                -ErrorAction Stop
            $packageBackedUp = $true
        }

        if ($hadExistingRegistry) {
            Copy-WPCTRegistryTransferKey `
                -SourcePath $regPath `
                -DestinationPath $registryBackupPath | Out-Null
            $registryBackedUp = $true
            Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
            if (Test-Path -Path $regPath) {
                throw "Existing registry key could not be staged for overwrite: $regPath"
            }
            $existingRegistryRemoved = $true
        }

        New-WPCTRegistryTransferKey `
            -RegistryPath $regPath `
            -TransferId $transferId `
            -RandomSecret $random `
            -BindingFields $fields

        Assert-WPCTPathHasNoReparsePoint -LiteralPath $SecretFilePath | Out-Null
        Move-Item `
            -LiteralPath $temporaryPath `
            -Destination $SecretFilePath `
            -ErrorAction Stop
        $newPackageCommitted = $true

        Remove-Item `
            -Path $registryStagePath `
            -Recurse `
            -Force `
            -ErrorAction Stop
        if (Test-Path -Path $registryStagePath) {
            throw "Registry staging key cleanup failed: $registryStagePath"
        }
        $commitCompleted = $true

        $postCommitErrors = New-Object System.Collections.Generic.List[string]
        if ($registryBackedUp) {
            try {
                Remove-Item `
                    -Path $registryBackupPath `
                    -Recurse `
                    -Force `
                    -ErrorAction Stop
                if (Test-Path -Path $registryBackupPath) {
                    throw "Previous registry backup remains: $registryBackupPath"
                }
            }
            catch {
                $postCommitErrors.Add($_.Exception.Message)
            }
        }
        if ($packageBackedUp) {
            try {
                Remove-Item `
                    -LiteralPath $packageBackupPath `
                    -Force `
                    -ErrorAction Stop
                if (Test-Path -LiteralPath $packageBackupPath) {
                    throw "Previous package backup remains: $packageBackupPath"
                }
            }
            catch {
                $postCommitErrors.Add($_.Exception.Message)
            }
        }

        if ($postCommitErrors.Count -gt 0) {
            return New-WPCTResult $false ([pscustomobject]@{
                Committed = $true
                CleanupComplete = $false
                TransferId = $transferId.ToString('D')
                SecretFilePath = $SecretFilePath
                RegistryPath = $regPath
                PackageBackupPath = if (
                    Test-Path -LiteralPath $packageBackupPath
                ) { $packageBackupPath } else { $null }
                RegistryBackupPath = if (
                    Test-Path -Path $registryBackupPath
                ) { $registryBackupPath } else { $null }
            }) ('Replacement committed but backup cleanup failed: {0}' -f (
                $postCommitErrors -join ' | '
            ))
        }

        New-WPCTResult $true ([pscustomobject]@{
            EngineVersion=$script:WPCTEngineVersion
            TransferId=$transferId.ToString('D')
            SecretFilePath=$SecretFilePath
            RegistryPath=$regPath
            BindingFields=$fields
            BindingMode=if($fields.Count-eq 0){'RandomSecretOnly'}else{$fields-join'+'}
            SecretCount=$serializable.Count
            Committed=$true
            CleanupComplete=$true
            Warnings=@()
        })
    } catch {
        $originalError = $_.Exception.Message
        $rollbackErrors = New-Object System.Collections.Generic.List[string]

        if (-not $commitCompleted) {
            if (
                $newPackageCommitted -and
                (Test-Path -LiteralPath $SecretFilePath)
            ) {
                try {
                    Remove-Item -LiteralPath $SecretFilePath -Force -ErrorAction Stop
                }
                catch {
                    $rollbackErrors.Add("New package removal failed: $($_.Exception.Message)")
                }
            }

            if ($packageBackedUp -and (Test-Path -LiteralPath $packageBackupPath)) {
                try {
                    Move-Item `
                        -LiteralPath $packageBackupPath `
                        -Destination $SecretFilePath `
                        -Force `
                        -ErrorAction Stop
                }
                catch {
                    $rollbackErrors.Add("Previous package restoration failed: $($_.Exception.Message)")
                }
            }

            if (
                (Test-WPCTRegistryOwnership -RegistryPath $regPath -TransferId $transferId)
            ) {
                try {
                    Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
                }
                catch {
                    $rollbackErrors.Add("New registry key removal failed: $($_.Exception.Message)")
                }
            }

            if ($registryBackedUp -and (Test-Path -Path $registryBackupPath)) {
                try {
                    if ($existingRegistryRemoved) {
                        if (Test-Path -Path $regPath) {
                            throw "Target registry path still exists: $regPath"
                        }
                        Copy-WPCTRegistryTransferKey `
                            -SourcePath $registryBackupPath `
                            -DestinationPath $regPath | Out-Null
                    }
                    elseif (-not (Test-WPCTRegistryTransferMarker `
                            -RegistryPath $regPath `
                            -TransferId $existingId)) {
                        throw "Original registry key verification failed: $regPath"
                    }

                    Remove-Item `
                        -Path $registryBackupPath `
                        -Recurse `
                        -Force `
                        -ErrorAction Stop
                    if (Test-Path -Path $registryBackupPath) {
                        throw "Registry backup cleanup failed: $registryBackupPath"
                    }
                }
                catch {
                    $rollbackErrors.Add("Previous registry restoration failed: $($_.Exception.Message)")
                }
            }
        }

        if (
            -not [string]::IsNullOrWhiteSpace($registryStagePath) -and
            (Test-WPCTRegistryOwnership -RegistryPath $registryStagePath -TransferId $transferId)
        ) {
            try {
                Remove-Item `
                    -Path $registryStagePath `
                    -Recurse `
                    -Force `
                    -ErrorAction Stop
                if (Test-Path -Path $registryStagePath) {
                    throw "Registry staging key remains: $registryStagePath"
                }
            }
            catch {
                $rollbackErrors.Add($_.Exception.Message)
            }
        }
        if (
            -not [string]::IsNullOrWhiteSpace($temporaryPath) -and
            (Test-Path -LiteralPath $temporaryPath)
        ) {
            try {
                Remove-Item `
                    -LiteralPath $temporaryPath `
                    -Force `
                    -ErrorAction Stop
                if (Test-Path -LiteralPath $temporaryPath) {
                    throw "Temporary package remains: $temporaryPath"
                }
            }
            catch {
                $rollbackErrors.Add($_.Exception.Message)
            }
        }

        $errorMessage = $originalError
        if ($rollbackErrors.Count -gt 0) {
            $errorMessage = '{0} Rollback errors: {1}' -f `
                $originalError, ($rollbackErrors -join ' | ')
        }
        New-WPCTResult $false ([pscustomobject]@{
            RolledBack = ($rollbackErrors.Count -eq 0)
            PackageBackupPath = if (
                -not [string]::IsNullOrWhiteSpace($packageBackupPath) -and
                (Test-Path -LiteralPath $packageBackupPath)
            ) { $packageBackupPath } else { $null }
            RegistryBackupPath = if (
                -not [string]::IsNullOrWhiteSpace($registryBackupPath) -and
                (Test-Path -Path $registryBackupPath)
            ) { $registryBackupPath } else { $null }
            RegistryStagePath = if (
                -not [string]::IsNullOrWhiteSpace($registryStagePath) -and
                (Test-Path -Path $registryStagePath)
            ) { $registryStagePath } else { $null }
            TemporaryPackagePath = if (
                -not [string]::IsNullOrWhiteSpace($temporaryPath) -and
                (Test-Path -LiteralPath $temporaryPath)
            ) { $temporaryPath } else { $null }
        }) $errorMessage
    } finally {
        foreach ($secret in @($serializable)) {
            if ($null -ne $secret.PSObject.Properties['Password']) {
                $secret.Password = $null
            }
        }
        $payload = $null
        $serializable = @()
        Clear-WPCTByteArray $random
        Clear-WPCTByteArray $plain
        Clear-WPCTByteArray $package
        if ($null -ne $keys) {
            Clear-WPCTByteArray $keys.EncryptionKey
            Clear-WPCTByteArray $keys.MacKey
        }
    }
}

function Read-WPCTCredentialTransfer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$SecretFilePath,
        [string]$RegistrySubKey=$script:WPCTDefaults.RegistrySubKey,
        [string[]]$RequiredSecretIds=@(),
        [object]$MachineIdentity=$null,
        [ValidateRange(1024, 104857600)][int64]$MaximumPackageBytes=$script:WPCTDefaults.MaximumPackageBytes
    )

    [byte[]]$random = $null
    [byte[]]$package = $null
    [byte[]]$plain = $null
    $keys = $null
    $json = $null

    try {
        $RegistrySubKey = Resolve-WPCTRegistrySubKey $RegistrySubKey
        if (-not (Test-Path -LiteralPath $SecretFilePath -PathType Leaf)) {
            throw "Secret package not found: $SecretFilePath"
        }

        $SecretFilePath = Assert-WPCTPathHasNoReparsePoint -LiteralPath $SecretFilePath
        $regPath = Join-Path 'HKLM:\SOFTWARE' $RegistrySubKey
        $data = Get-ItemProperty -Path $regPath -ErrorAction Stop
        [byte[]]$random = $data.($script:WPCTDefaults.RandomSecretValueName)
        [string[]]$fields = @($data.($script:WPCTDefaults.BindingFieldsValueName))
        [int]$schema = $data.($script:WPCTDefaults.SchemaVersionValueName)
        $registryTransferId = [guid]::Empty

        if (-not [guid]::TryParse(
                [string]$data.($script:WPCTDefaults.TransferIdValueName),
                [ref]$registryTransferId
            )) {
            throw 'Registry contains an invalid TransferId.'
        }

        if (-not (Test-WPCTRegistryTransferMarker `
                -RegistryPath $regPath `
                -TransferId $registryTransferId)) {
            throw "Registry ownership metadata could not be verified: $regPath"
        }

        if ($schema -ne $script:WPCTDefaults.RegistrySchemaVersion) {
            throw "Unsupported registry schema version: $schema"
        }
        if ($null -eq $random -or $random.Length -ne 32) {
            throw 'RandomSecret must contain exactly 32 bytes.'
        }
        if ($null -eq $MachineIdentity) {
            $MachineIdentity = Get-WPCTMachineIdentity
        }

        $keys = New-WPCTDerivedKeys $random $MachineIdentity $fields
        $package = Read-WPCTBoundedFile `
            -LiteralPath $SecretFilePath `
            -MaximumBytes $MaximumPackageBytes

        $plain = Unprotect-WPCTBytes `
            -PackageBytes $package `
            -EncryptionKey $keys.EncryptionKey `
            -MacKey $keys.MacKey
        $json = [Text.Encoding]::UTF8.GetString($plain)
        $payload = $json | ConvertFrom-Json
        Test-WPCTPayload $payload $RequiredSecretIds | Out-Null

        if ([string]$payload.TransferId -ne $registryTransferId.ToString('D')) {
            throw 'Authenticated transfer ID does not match registry ownership metadata.'
        }

        $payloadBindingFields = @($payload.BindingFields) -join '|'
        $registryBindingFields = $fields -join '|'
        if ($payloadBindingFields -ne $registryBindingFields) {
            throw 'Authenticated binding fields do not match registry metadata.'
        }

        New-WPCTResult $true $payload
    }
    catch {
        New-WPCTResult $false $null $_.Exception.Message
    }
    finally {
        Clear-WPCTByteArray $random
        Clear-WPCTByteArray $package
        Clear-WPCTByteArray $plain
        $json = $null
        if ($null -ne $keys) {
            Clear-WPCTByteArray $keys.EncryptionKey
            Clear-WPCTByteArray $keys.MacKey
        }
    }
}

function Export-WPCTCredentialClixml {
    <#
    .DESCRIPTION
        Exports every credential as DPAPI-protected CLIXML under the account
        running this function. The output directory is selected by the caller.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]$Payload,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$OutputDirectory,
        [switch]$AllowOverwrite
    )

    $transactionId = [guid]::NewGuid().ToString('N')
    $stagingDirectory = $null
    $backupDirectory = $null
    $committedFiles = New-Object System.Collections.Generic.List[string]
    $backups = @{}
    $preserveBackup = $false
    $commitCompleted = $false

    try {
        $OutputDirectory = Assert-WPCTPathHasNoReparsePoint -LiteralPath $OutputDirectory
        $parent = Split-Path -Parent $OutputDirectory
        if ([string]::IsNullOrWhiteSpace($parent)) {
            $parent = (Get-Location).Path
        }
        $stagingDirectory = Join-Path $parent ".wpct-stage-$transactionId"
        $backupDirectory = Join-Path $parent ".wpct-backup-$transactionId"

        New-Item -ItemType Directory -Path $stagingDirectory -ErrorAction Stop | Out-Null
        Set-WPCTCredentialDirectoryAcl -LiteralPath $stagingDirectory

        foreach ($secret in @($Payload.Secrets)) {
            $destinationPath = Join-Path $OutputDirectory ($secret.Id + '.xml')
            if ((Test-Path -LiteralPath $destinationPath) -and -not $AllowOverwrite) {
                throw "Credential file already exists. Use -AllowOverwrite to replace it: $destinationPath"
            }

            $secure = ConvertTo-SecureString ([string]$secret.Password) -AsPlainText -Force
            $credential = New-Object Management.Automation.PSCredential(
                [string]$secret.Username,
                $secure
            )
            $stagedPath = Join-Path $stagingDirectory ($secret.Id + '.xml')
            $credential | Export-Clixml -LiteralPath $stagedPath -Force -ErrorAction Stop
            $verify = Import-Clixml -LiteralPath $stagedPath -ErrorAction Stop
            if (
                $verify -isnot [Management.Automation.PSCredential] -or
                $verify.UserName -ne [string]$secret.Username
            ) {
                throw "CLIXML verification failed for '$($secret.Id)'."
            }

            $secure = $null
            $credential = $null
            $verify = $null
        }

        New-Item -ItemType Directory -Path $OutputDirectory -Force -ErrorAction Stop | Out-Null
        Set-WPCTCredentialDirectoryAcl -LiteralPath $OutputDirectory

        if ($AllowOverwrite) {
            New-Item -ItemType Directory -Path $backupDirectory -ErrorAction Stop | Out-Null
            Set-WPCTCredentialDirectoryAcl -LiteralPath $backupDirectory
        }

        foreach ($secret in @($Payload.Secrets)) {
            $destinationPath = Join-Path $OutputDirectory ($secret.Id + '.xml')
            $stagedPath = Join-Path $stagingDirectory ($secret.Id + '.xml')
            Assert-WPCTPathHasNoReparsePoint -LiteralPath $destinationPath | Out-Null
            Assert-WPCTPathHasNoReparsePoint -LiteralPath $stagedPath | Out-Null

            if (Test-Path -LiteralPath $destinationPath) {
                $backupPath = Join-Path $backupDirectory ($secret.Id + '.xml')
                Assert-WPCTPathHasNoReparsePoint -LiteralPath $backupPath | Out-Null
                Move-Item -LiteralPath $destinationPath -Destination $backupPath -ErrorAction Stop
                $backups[$destinationPath] = $backupPath
            }

            Move-Item -LiteralPath $stagedPath -Destination $destinationPath -ErrorAction Stop
            $committedFiles.Add($destinationPath)
        }

        $commitCompleted = $true
        $cleanupErrors = New-Object System.Collections.Generic.List[string]

        try {
            Remove-Item `
                -LiteralPath $stagingDirectory `
                -Recurse `
                -Force `
                -ErrorAction Stop
            if (Test-Path -LiteralPath $stagingDirectory) {
                throw "Credential staging directory remains: $stagingDirectory"
            }
            $stagingDirectory = $null
        }
        catch {
            $cleanupErrors.Add($_.Exception.Message)
        }

        if ($AllowOverwrite) {
            try {
                Remove-Item `
                    -LiteralPath $backupDirectory `
                    -Recurse `
                    -Force `
                    -ErrorAction Stop
                if (Test-Path -LiteralPath $backupDirectory) {
                    throw "Credential backup directory remains: $backupDirectory"
                }
                $backupDirectory = $null
            }
            catch {
                $cleanupErrors.Add($_.Exception.Message)
            }
        }

        if ($cleanupErrors.Count -gt 0) {
            return New-WPCTResult $false ([pscustomobject]@{
                Committed = $true
                CleanupComplete = $false
                ClixmlFiles = $committedFiles.ToArray()
                OutputDirectory = $OutputDirectory
                StagingDirectory = if (
                    -not [string]::IsNullOrWhiteSpace($stagingDirectory) -and
                    (Test-Path -LiteralPath $stagingDirectory)
                ) { $stagingDirectory } else { $null }
                BackupDirectory = if (
                    -not [string]::IsNullOrWhiteSpace($backupDirectory) -and
                    (Test-Path -LiteralPath $backupDirectory)
                ) { $backupDirectory } else { $null }
                CleanupErrors = $cleanupErrors.ToArray()
            }) ('Credential files committed but transaction cleanup failed: {0}' -f (
                $cleanupErrors -join ' | '
            ))
        }

        New-WPCTResult $true ([pscustomobject]@{
            ClixmlFiles = $committedFiles.ToArray()
            OutputDirectory = $OutputDirectory
            Transactional = $true
            AclProtected = $true
            Committed = $true
            CleanupComplete = $true
        })
    }
    catch {
        $originalError = $_.Exception.Message
        $rollbackErrors = New-Object System.Collections.Generic.List[string]

        foreach ($path in @($committedFiles.ToArray())) {
            try {
                if (Test-Path -LiteralPath $path) {
                    Assert-WPCTPathHasNoReparsePoint -LiteralPath $path | Out-Null
                    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
                }
            }
            catch {
                $rollbackErrors.Add(
                    "New credential removal failed for '$path': $($_.Exception.Message)"
                )
            }
        }

        foreach ($destinationPath in @($backups.Keys)) {
            $backupPath = $backups[$destinationPath]
            if (Test-Path -LiteralPath $backupPath) {
                try {
                    Assert-WPCTPathHasNoReparsePoint -LiteralPath $backupPath | Out-Null
                    Assert-WPCTPathHasNoReparsePoint -LiteralPath $destinationPath | Out-Null
                    Move-Item `
                        -LiteralPath $backupPath `
                        -Destination $destinationPath `
                        -Force `
                        -ErrorAction Stop
                }
                catch {
                    $rollbackErrors.Add(
                        "Credential restoration failed for '$destinationPath': $($_.Exception.Message)"
                    )
                }
            }
        }

        if (
            -not [string]::IsNullOrWhiteSpace($stagingDirectory) -and
            (Test-Path -LiteralPath $stagingDirectory)
        ) {
            try {
                Remove-Item `
                    -LiteralPath $stagingDirectory `
                    -Recurse `
                    -Force `
                    -ErrorAction Stop
                if (Test-Path -LiteralPath $stagingDirectory) {
                    throw "Credential staging directory remains: $stagingDirectory"
                }
                $stagingDirectory = $null
            }
            catch {
                $rollbackErrors.Add($_.Exception.Message)
            }
        }

        if (
            $rollbackErrors.Count -eq 0 -and
            -not [string]::IsNullOrWhiteSpace($backupDirectory) -and
            (Test-Path -LiteralPath $backupDirectory)
        ) {
            try {
                Remove-Item `
                    -LiteralPath $backupDirectory `
                    -Recurse `
                    -Force `
                    -ErrorAction Stop
                if (Test-Path -LiteralPath $backupDirectory) {
                    throw "Credential backup directory remains: $backupDirectory"
                }
                $backupDirectory = $null
            }
            catch {
                $rollbackErrors.Add($_.Exception.Message)
            }
        }

        $preserveBackup = $rollbackErrors.Count -gt 0
        $errorMessage = $originalError
        if ($preserveBackup) {
            $errorMessage = '{0} Rollback errors: {1}' -f `
                $errorMessage, ($rollbackErrors -join ' | ')
        }

        New-WPCTResult $false ([pscustomobject]@{
            ClixmlFiles = @()
            OutputDirectory = $OutputDirectory
            Transactional = $true
            RolledBack = (-not $preserveBackup)
            Committed = $commitCompleted
            BackupDirectory = if (
                $preserveBackup -and
                -not [string]::IsNullOrWhiteSpace($backupDirectory) -and
                (Test-Path -LiteralPath $backupDirectory)
            ) { $backupDirectory } else { $null }
            StagingDirectory = if (
                -not [string]::IsNullOrWhiteSpace($stagingDirectory) -and
                (Test-Path -LiteralPath $stagingDirectory)
            ) { $stagingDirectory } else { $null }
            RollbackErrors = $rollbackErrors.ToArray()
        }) $errorMessage
    }
    finally {
        foreach ($secret in @($Payload.Secrets)) {
            if ($null -ne $secret.PSObject.Properties['Password']) {
                $secret.Password = $null
            }
        }
    }
}

function Remove-WPCTCredentialTransfer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$SecretFilePath,
        [string]$RegistrySubKey=$script:WPCTDefaults.RegistrySubKey,
        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if ($_ -eq [guid]::Empty) {
                throw 'TransferId cannot be empty during cleanup.'
            }
            return $true
        })]
        [guid]$TransferId,

        [ValidateRange(1024, 104857600)]
        [int64]$MaximumPackageBytes = $script:WPCTDefaults.MaximumPackageBytes
    )

    $packageRemoved = $false
    $temporaryFileRemoved = $false
    $registryKeyRemoved = $false
    $warnings = New-Object System.Collections.Generic.List[string]
    $authenticatedPayload = $null

    try {
        $RegistrySubKey = Resolve-WPCTRegistrySubKey $RegistrySubKey
        $SecretFilePath = Assert-WPCTPathHasNoReparsePoint -LiteralPath $SecretFilePath
        $regPath = Join-Path 'HKLM:\SOFTWARE' $RegistrySubKey

        if (-not (Test-WPCTRegistryTransferMarker `
                -RegistryPath $regPath `
                -TransferId $TransferId)) {
            throw "Refusing cleanup because registry ownership could not be verified: $regPath"
        }

        $read = Read-WPCTCredentialTransfer `
            -SecretFilePath $SecretFilePath `
            -RegistrySubKey $RegistrySubKey `
            -MaximumPackageBytes $MaximumPackageBytes
        if (-not $read.Success) {
            throw "Refusing cleanup because package ownership could not be authenticated: $($read.Error)"
        }
        $authenticatedPayload = $read.Payload
        if ([guid]$authenticatedPayload.TransferId -ne $TransferId) {
            throw 'Refusing cleanup because the authenticated package TransferId does not match.'
        }

        $temporaryPath = '{0}.{1}.tmp' -f $SecretFilePath, $TransferId.ToString('N')
        Assert-WPCTPathHasNoReparsePoint -LiteralPath $temporaryPath | Out-Null
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction Stop
        }
        $temporaryFileRemoved = -not (Test-Path -LiteralPath $temporaryPath)
        if (-not $temporaryFileRemoved) {
            throw "Temporary package cleanup failed: $temporaryPath"
        }

        Assert-WPCTPathHasNoReparsePoint -LiteralPath $SecretFilePath | Out-Null
        Remove-Item -LiteralPath $SecretFilePath -Force -ErrorAction Stop
        $packageRemoved = -not (Test-Path -LiteralPath $SecretFilePath)
        if (-not $packageRemoved) {
            throw "Secret package cleanup failed: $SecretFilePath"
        }

        if (Test-Path -Path $regPath) {
            Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
        }
        $registryKeyRemoved = -not (Test-Path -Path $regPath)

        if (Test-Path -Path $regPath) {
            throw "Registry bootstrap cleanup failed: $regPath"
        }

        New-WPCTResult $true ([pscustomobject]@{
            PackageRemoved = $packageRemoved
            TemporaryFileRemoved = $temporaryFileRemoved
            RegistryKeyRemoved = $registryKeyRemoved
            TransferId = $TransferId.ToString('D')
            Warnings = $warnings.ToArray()
        })
    }
    catch {
        New-WPCTResult $false ([pscustomobject]@{
            PackageRemoved = $packageRemoved
            TemporaryFileRemoved = $temporaryFileRemoved
            RegistryKeyRemoved = $registryKeyRemoved
            TransferId = $TransferId.ToString('D')
            Warnings = $warnings.ToArray()
        }) $_.Exception.Message
    }
    finally {
        if ($null -ne $authenticatedPayload) {
            foreach ($secret in @($authenticatedPayload.Secrets)) {
                if ($null -ne $secret.PSObject.Properties['Password']) {
                    $secret.Password = $null
                }
            }
        }
    }
}

function Invoke-WPCTCredentialImport {
    <# One call: decrypt, create CLIXML for current administrator, then cleanup. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$SecretFilePath,
        [Parameter(Mandatory=$true)][string]$OutputDirectory,
        [string]$RegistrySubKey=$script:WPCTDefaults.RegistrySubKey,
        [string[]]$RequiredSecretIds=@(),
        [switch]$KeepTransfer,
        [switch]$AllowClixmlOverwrite,
        [ValidateRange(1024, 104857600)][int64]$MaximumPackageBytes=$script:WPCTDefaults.MaximumPackageBytes
    )

    $read = Read-WPCTCredentialTransfer `
        -SecretFilePath $SecretFilePath `
        -RegistrySubKey $RegistrySubKey `
        -RequiredSecretIds $RequiredSecretIds `
        -MaximumPackageBytes $MaximumPackageBytes
    if (-not $read.Success) {
        return $read
    }

    $transferId = [guid]$read.Payload.TransferId
    $export = Export-WPCTCredentialClixml `
        -Payload $read.Payload `
        -OutputDirectory $OutputDirectory `
        -AllowOverwrite:$AllowClixmlOverwrite
    if (-not $export.Success) {
        return $export
    }

    $cleanup = $null
    if (-not $KeepTransfer) {
        $cleanup = Remove-WPCTCredentialTransfer `
            -SecretFilePath $SecretFilePath `
            -RegistrySubKey $RegistrySubKey `
            -TransferId $transferId `
            -MaximumPackageBytes $MaximumPackageBytes
        if (-not $cleanup.Success) {
            return $cleanup
        }
    }

    New-WPCTResult $true ([pscustomobject]@{
        EngineVersion = $script:WPCTEngineVersion
        TransferId = $transferId.ToString('D')
        ClixmlFiles = $export.Payload.ClixmlFiles
        CreatedFor = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        CleanedUp = (-not $KeepTransfer)
        Cleanup = if ($null -eq $cleanup) { $null } else { $cleanup.Payload }
    })
}

#endregion Credential transfer workflow
