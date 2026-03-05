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
    [switch]$x,
    [string]$o=""
)

# ----------- helpers -------------

function __l($t){ if($x){ Write-Host ("[+]"+$t) -F Cyan } }

function __e($p){
    if(!$p){ return $null }
    return [Environment]::ExpandEnvironmentVariables($p)
}

function __acl($p){

    if(!(Test-Path $p)){ return $false }

    try{
        $a = Get-Acl -LiteralPath $p
        $u = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        foreach($i in $a.Access){

            if($i.AccessControlType -ne "Allow"){ continue }

            $r = $i.FileSystemRights.ToString()

            if($r -match "Write|Modify|Full"){

                if(
                    $i.IdentityReference -match "Users" -or
                    $i.IdentityReference -match "Everyone" -or
                    $i.IdentityReference.Value -eq $u
                ){
                    return $true
                }
            }
        }
    }catch{}

    return $false
}

function __dir($p){
    try{
        $d = Split-Path $p -Parent
        return __acl $d
    }catch{ return $false }
}

function __sc($u,$f,$d){

    $s = 0

    if($u -match "SYSTEM"){ $s += 50 }
    elseif($u -match "Admin"){ $s += 40 }

    if($f){ $s += 30 }
    if($d){ $s += 20 }

    return $s
}

# -------- storage ---------

$out = @()

# =====================================================
# POLICY CHECK
# =====================================================

__l "policy"

$k1 = "HKLM:\Software\Policies\Microsoft\Windows\Installer"
$k2 = "HKCU:\Software\Policies\Microsoft\Windows\Installer"

$p1 = Get-ItemProperty $k1 -EA 0
$p2 = Get-ItemProperty $k2 -EA 0

if(($p1.AlwaysInstallElevated -eq 1) -and ($p2.AlwaysInstallElevated -eq 1)){

    $out += [pscustomobject]@{
        A="Policy"
        B="AlwaysInstallElevated"
        C="msiexec"
        D="SYSTEM"
        E=$true
        F=$true
        S=100
    }
}

# =====================================================
# SERVICES
# =====================================================

__l "svc"

Get-CimInstance Win32_Service -EA 0 | ForEach-Object{

    $raw = $_.PathName
    if(!$raw){ return }

    $p = ($raw -replace '"','').Split(" ")[0]
    $p = __e $p

    if($p -notmatch "\.(exe|msi)$"){ return }
    if(!(Test-Path $p)){ return }

    $fw = __acl $p
    $fd = __dir $p

    if(!($fw -or $fd)){ return }

    $out += [pscustomobject]@{

        A="Svc"
        B=$_.Name
        C=$p
        D=$_.StartName
        E=$fw
        F=$fd
        S=(__sc $_.StartName $fw $fd)
    }
}

# =====================================================
# TASKS
# =====================================================

__l "task"

Get-ScheduledTask -EA 0 | ForEach-Object{

    $usr = $_.Principal.UserId

    foreach($act in $_.Actions){

        $exe = __e $act.Execute
        if(!$exe){ continue }

        if($exe -notmatch "\.(exe|msi)$"){ continue }
        if(!(Test-Path $exe)){ continue }

        $fw = __acl $exe
        $fd = __dir $exe

        if(!($fw -or $fd)){ continue }

        $out += [pscustomobject]@{

            A="Task"
            B=$_.TaskName
            C=$exe
            D=$usr
            E=$fw
            F=$fd
            S=(__sc $usr $fw $fd)
        }
    }
}

# =====================================================
# UNINSTALL
# =====================================================

__l "uninstall"

$uA = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
$uB = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"

foreach($k in $uA,$uB){

    Get-ItemProperty $k -EA 0 | ForEach-Object{

        $cmd = $_.UninstallString
        if(!$cmd){ return }

        if($cmd -notmatch "\.(exe|msi)"){ return }

        $exe = __e ($cmd.Split(" ")[0].Replace('"',''))

        if(!(Test-Path $exe)){ return }

        $fw = __acl $exe
        $fd = __dir $exe

        if(!($fw -or $fd)){ return }

        $out += [pscustomobject]@{

            A="Uninst"
            B=$_.DisplayName
            C=$exe
            D="Admin"
            E=$fw
            F=$fd
            S=(__sc "Admin" $fw $fd)
        }
    }
}

# =====================================================
# PROGRAM FILES (Limited Depth - Still Deep Enough)
# =====================================================

__l "pf"

"$env:ProgramFiles","$env:ProgramFiles(x86)" | ForEach-Object{

    if(!(Test-Path $_)){ return }

    Get-ChildItem $_ -Recurse -Depth 2 -Include *.exe,*.msi -EA 0 | ForEach-Object{

        $fw = __acl $_.FullName
        $fd = __dir $_.FullName

        if(!($fw -or $fd)){ return }

        $out += [pscustomobject]@{

            A="PF"
            B=$_.Name
            C=$_.FullName
            D="Unknown"
            E=$fw
            F=$fd
            S=(__sc "" $fw $fd)
        }
    }
}

# =====================================================

$out = $out | Sort-Object S -Desc

$out | Format-Table -AutoSize

if($o){
    $out | Export-Csv $o -NoTypeInformation
}
