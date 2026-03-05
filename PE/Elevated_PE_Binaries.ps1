<#
Elevated Binary / MSI Privilege Escalation Auditor
-------------------------------------------------

Finds binaries installers or executables that:

1. Run as SYSTEM / Admin
2. Are writable by the current user

Detects:
 ✔ Writable service executables
 ✔ Writable scheduled task binaries
 ✔ Writable MSI installers
 ✔ AlwaysInstallElevated misconfiguration
 ✔ Writable uninstallers
 ✔ Writable binaries in Program Files
 ✔ Abuse scoring

Author: Security Audit Tool
#>

param(
    [switch]$VerboseMode,
    [string]$ExportCsv = ""
)

function V($msg){
    if($VerboseMode){
        Write-Host "[+] $msg" -ForegroundColor Cyan
    }
}

function Expand-PathSafe($p){
    if(!$p){ return $null }
    return [Environment]::ExpandEnvironmentVariables($p)
}

function Get-PathPermissions($Path){

    if(!(Test-Path $Path)){ return $null }

    try{
        $acl = Get-Acl $Path
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        foreach($ace in $acl.Access){

            if($ace.AccessControlType -ne "Allow"){ continue }

            if($ace.FileSystemRights -match "Write|Modify|FullControl"){

                if(
                    $ace.IdentityReference -match "Users" -or
                    $ace.IdentityReference -match "Everyone" -or
                    $ace.IdentityReference -match $user
                ){
                    return $true
                }
            }
        }

    }catch{}

    return $false
}

function Test-FolderWritable($Path){

    try{
        $folder = Split-Path $Path -Parent
        return Get-PathPermissions $folder
    }catch{
        return $false
    }
}

function Get-AbuseScore($user,$fileWritable,$folderWritable){

    $score = 0

    if($user -match "SYSTEM"){ $score += 50 }
    elseif($user -match "Admin"){ $score += 40 }

    if($fileWritable){ $score += 30 }
    if($folderWritable){ $score += 20 }

    return $score
}

$results = @()

# ------------------------------------------------
# ALWAYSINSTALLELEVATED CHECK
# ------------------------------------------------

V "Checking AlwaysInstallElevated..."

$HKLM = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
$HKCU = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue

if($HKLM.AlwaysInstallElevated -eq 1 -and $HKCU.AlwaysInstallElevated -eq 1){

    $results += [PSCustomObject]@{
        Source="Policy"
        Name="AlwaysInstallElevated"
        Execute="msiexec.exe"
        User="SYSTEM"
        FileWritable="True"
        FolderWritable="True"
        AbuseScore=100
    }
}

# ------------------------------------------------
# SERVICES
# ------------------------------------------------

V "Scanning services..."

Get-CimInstance Win32_Service | ForEach-Object{

    $path = ($_ .PathName -replace '"','').Split(" ")[0]

    if($path -notmatch "\.(exe|msi)$"){ return }

    $path = Expand-PathSafe $path

    if(!(Test-Path $path)){ return }

    $fileWritable = Get-PathPermissions $path
    $folderWritable = Test-FolderWritable $path

    if(!($fileWritable -or $folderWritable)){ return }

    $results += [PSCustomObject]@{

        Source="Service"
        Name=$_.Name
        Execute=$path
        User=$_.StartName
        FileWritable=$fileWritable
        FolderWritable=$folderWritable
        AbuseScore=Get-AbuseScore $_.StartName $fileWritable $folderWritable
    }

}

# ------------------------------------------------
# SCHEDULED TASKS
# ------------------------------------------------

V "Scanning scheduled tasks..."

Get-ScheduledTask | ForEach-Object{

    $user=$_.Principal.UserId

    foreach($act in $_.Actions){

        $exe = Expand-PathSafe $act.Execute

        if($exe -notmatch "\.(exe|msi)$"){ continue }

        if(!(Test-Path $exe)){ continue }

        $fileWritable = Get-PathPermissions $exe
        $folderWritable = Test-FolderWritable $exe

        if(!($fileWritable -or $folderWritable)){ continue }

        $results += [PSCustomObject]@{

            Source="ScheduledTask"
            Name="$($_.TaskPath)$($_.TaskName)"
            Execute=$exe
            User=$user
            FileWritable=$fileWritable
            FolderWritable=$folderWritable
            AbuseScore=Get-AbuseScore $user $fileWritable $folderWritable
        }

    }

}

# ------------------------------------------------
# UNINSTALLERS (MSI ABUSE)
# ------------------------------------------------

V "Scanning uninstall registry..."

$uninstallPaths=@(
"HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
"HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

foreach($path in $uninstallPaths){

    Get-ItemProperty $path -ErrorAction SilentlyContinue | ForEach-Object{

        $cmd=$_.UninstallString

        if(!$cmd){ return }

        if($cmd -notmatch "\.(exe|msi)"){ return }

        $exe=$cmd.Split(" ")[0].Replace('"','')

        if(!(Test-Path $exe)){ return }

        $fileWritable = Get-PathPermissions $exe
        $folderWritable = Test-FolderWritable $exe

        if(!($fileWritable -or $folderWritable)){ return }

        $results += [PSCustomObject]@{

            Source="UninstallEntry"
            Name=$_.DisplayName
            Execute=$exe
            User="SYSTEM/Admin"
            FileWritable=$fileWritable
            FolderWritable=$folderWritable
            AbuseScore=Get-AbuseScore "Admin" $fileWritable $folderWritable
        }

    }

}

# ------------------------------------------------
# PROGRAM FILES WRITEABLE BINARIES
# ------------------------------------------------

V "Scanning Program Files..."

$paths=@(
"$env:ProgramFiles",
"$env:ProgramFiles(x86)"
)

foreach($p in $paths){

    Get-ChildItem $p -Recurse -Include *.exe,*.msi -ErrorAction SilentlyContinue | ForEach-Object{

        $fileWritable = Get-PathPermissions $_.FullName
        $folderWritable = Test-FolderWritable $_.FullName

        if($fileWritable -or $folderWritable){

            $results += [PSCustomObject]@{

                Source="ProgramFilesBinary"
                Name=$_.Name
                Execute=$_.FullName
                User="Unknown"
                FileWritable=$fileWritable
                FolderWritable=$folderWritable
                AbuseScore=Get-AbuseScore "" $fileWritable $folderWritable
            }

        }

    }

}

# ------------------------------------------------
# OUTPUT
# ------------------------------------------------

$results = $results | Sort-Object AbuseScore -Descending

$results | Format-Table -AutoSize

if($ExportCsv){

    $results | Export-Csv $ExportCsv -NoTypeInformation
    Write-Host "CSV exported -> $ExportCsv"

}
