<#
Unquoted Service Path Finder
---------------------------------------------
Author: 0xTr4c3
#>

param(
    [switch]$xv,
    [string]$csv=""
)

function _l($m){ if($xv){ Write-Host ("[+]"+$m) -F Cyan } }

function _e($s){
    if(!$s){ return $null }
    return [Environment]::ExpandEnvironmentVariables($s)
}

function _acl($p){

    if(!(Test-Path $p)){ return $false }

    try{

        $a = Get-Acl -LiteralPath $p
        $u = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        foreach($i in $a.Access){

            if($i.AccessControlType -ne "Allow"){ continue }

            if($i.FileSystemRights.ToString() -match "Write|Modify|Full"){

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

function _dir($p){
    try{
        return _acl (Split-Path $p -Parent)
    }catch{
        return $false
    }
}

function _score($u,$w){

    $s = 0

    if($u -match "SYSTEM"){ $s += 50 }
    elseif($u -match "LocalSystem"){ $s += 50 }
    elseif($u -match "Admin"){ $s += 40 }

    if($w){ $s += 40 }

    return $s
}

$r = @()

# ===============================
# Scan Services
# ===============================

_l "svc"

Get-CimInstance Win32_Service -EA 0 | ForEach-Object{

    $u = $_.StartName
    $p = $_.PathName

    if(!$p){ return }

    $clean = ($p -replace '"','')
    $clean = _e ($clean.Split(" ")[0])

    if($u -notmatch "SYSTEM|LocalSystem|Admin"){ return }

    if($p -match '^"'){ return }

    if($clean -notmatch "\s"){ return }
    if(!(Test-Path $clean)){ return }

    # Build path chain
    $parts = $clean.Split("\")
    $acc = ""
    $dirs = @()

    foreach($x in $parts){

        $acc += "$x\"

        if(Test-Path $acc){
            $dirs += $acc
        }
    }

    $hit = $false

    foreach($d in $dirs){

        if(_acl $d){
            $hit = $true
            break
        }
    }

    if(!$hit){ return }

    $r += [pscustomobject]@{

        A="UnquotedSvc"
        B=$_.Name
        C=$clean
        D=$u
        E=$hit
        S=_score $u $hit
    }

}

# ===============================
# Sort + Output
# ===============================

$r = $r | Sort-Object S -Descending

$r | Format-Table -AutoSize

if($csv){
    $r | Export-Csv $csv -NoTypeInformation
}
