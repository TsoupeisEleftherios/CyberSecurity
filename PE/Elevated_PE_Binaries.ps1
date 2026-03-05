<#
Elevated Binary / MSI Privilege Escalation Tool
-------------------------------------------------
Author: 0xTr4c3
#>

param(
    [switch]$z,
    [string]$out=""
)

function _l($m){ if($z){ Write-Host ("[+]"+$m) -F Cyan } }

function _e($p){
    if(!$p){ return $null }
    return [Environment]::ExpandEnvironmentVariables($p)
}

function _w($p){

    if(!(Test-Path $p)){ return $false }

    try{

        $a = Get-Acl -LiteralPath $p
        $u = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        foreach($x in $a.Access){

            if($x.AccessControlType -ne "Allow"){ continue }

            if($x.FileSystemRights.ToString() -match "Write|Modify|Full"){

                if(
                    $x.IdentityReference -match "Users" -or
                    $x.IdentityReference -match "Everyone" -or
                    $x.IdentityReference.Value -eq $u
                ){
                    return $true
                }
            }
        }

    }catch{}

    return $false
}

function _d($p){
    try{ return _w (Split-Path $p -Parent) }
    catch{ return $false }
}

function _s($u,$f,$d){
    $x=0
    if($u -match "SYSTEM"){ $x+=50 }
    elseif($u -match "LocalSystem"){ $x+=50 }
    elseif($u -match "Admin"){ $x+=40 }

    if($f){ $x+=30 }
    if($d){ $x+=20 }

    return $x
}

$r=@()

# File patterns now include DLL
$ext = "\.(exe|msi|dll)$"

# =====================================================
# Policy
# =====================================================

_l "pol"

$p1 = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\Installer" -EA 0
$p2 = Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\Installer" -EA 0

if(($p1.AlwaysInstallElevated -eq 1) -and ($p2.AlwaysInstallElevated -eq 1)){

    $r += [pscustomobject]@{
        A="Pol"
        B="AlwaysInstallElevated"
        C="msiexec"
        D="SYSTEM"
        E=$true
        F=$true
        S=100
    }
}

# =====================================================
# Services
# =====================================================

_l "svc"

Get-CimInstance Win32_Service -EA 0 | ForEach-Object{

    $raw=$_.PathName
    if(!$raw){ return }

    $p=_e(($raw -replace '"','').Split(" ")[0])

    if($p -notmatch $ext){ return }
    if(!(Test-Path $p)){ return }

    $fw=_w $p
    $fd=_d $p

    if(!($fw -or $fd)){ return }

    $r += [pscustomobject]@{
        A="Svc"
        B=$_.Name
        C=$p
        D=$_.StartName
        E=$fw
        F=$fd
        S=(_s $_.StartName $fw $fd)
    }
}

# =====================================================
# Tasks
# =====================================================

_l "tsk"

Get-ScheduledTask -EA 0 | ForEach-Object{

    $u=$_.Principal.UserId

    foreach($a in $_.Actions){

        $exe=_e $a.Execute
        if(!$exe){ continue }

        if($exe -notmatch $ext){ continue }
        if(!(Test-Path $exe)){ continue }

        $fw=_w $exe
        $fd=_d $exe

        if(!($fw -or $fd)){ continue }

        $r += [pscustomobject]@{
            A="Task"
            B=$_.TaskName
            C=$exe
            D=$u
            E=$fw
            F=$fd
            S=(_s $u $fw $fd)
        }
    }
}

# =====================================================
# Uninstall
# =====================================================

_l "uni"

$u1="HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
$u2="HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"

foreach($k in $u1,$u2){

    Get-ItemProperty $k -EA 0 | ForEach-Object{

        $cmd=$_.UninstallString
        if(!$cmd){ return }

        if($cmd -notmatch $ext){ return }

        $exe=_e ($cmd.Split(" ")[0].Replace('"',''))

        if(!(Test-Path $exe)){ return }

        $fw=_w $exe
        $fd=_d $exe

        if(!($fw -or $fd)){ return }

        $r += [pscustomobject]@{
            A="Uninst"
            B=$_.DisplayName
            C=$exe
            D="Admin"
            E=$fw
            F=$fd
            S=(_s "Admin" $fw $fd)
        }
    }
}

# =====================================================
# Program Files
# =====================================================

_l "pf"

"$env:ProgramFiles","$env:ProgramFiles(x86)" | ForEach-Object{

    if(!(Test-Path $_)){ return }

    Get-ChildItem $_ -Recurse -Depth 2 -Include *.exe,*.msi,*.dll -EA 0 | ForEach-Object{

        $fw=_w $_.FullName
        $fd=_d $_.FullName

        if(!($fw -or $fd)){ return }

        $r += [pscustomobject]@{
            A="PF"
            B=$_.Name
            C=$_.FullName
            D="Unknown"
            E=$fw
            F=$fd
            S=(_s "" $fw $fd)
        }
    }
}

# =====================================================

$r = $r | Sort-Object S -Desc

$r | Format-Table -AutoSize

if($out){
    $r | Export-Csv $out -NoTypeInformation
}
