<#
Unquoted Service Path Finder - Full Corrected Version
---------------------------------------------
Author: 0xTr4c3
#>

param(
    [switch]$xv
)

function _l($m){ if($xv){ Write-Host "[+] $m" -ForegroundColor Cyan } }

function _e($s){
    if(!$s){ return $null }
    return [Environment]::ExpandEnvironmentVariables($s)
}

function Get-Permissions($Path){

    if(!(Test-Path $Path)){ return $null }

    try{
        $acl = Get-Acl -LiteralPath $Path
        $me  = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        $perms = @()

        foreach($ace in $acl.Access){

            if($ace.AccessControlType -ne "Allow"){ continue }

            $rights = $ace.FileSystemRights.ToString()
            $writable = $rights -match "Write|Modify|Full"

            $isMine =
                $ace.IdentityReference.Value -eq $me -or
                $ace.IdentityReference.Value -match "Users|Everyone|Authenticated"

            $perms += [pscustomobject]@{
                Identity = $ace.IdentityReference.Value
                Rights   = $rights
                Writable = ($writable -and $isMine)
            }
        }

        return $perms
    }
    catch{
        return $null
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

_l "Scanning services..."

Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {

    $serviceName = $_.Name
    $user        = $_.StartName
    $rawPath     = $_.PathName

    if(!$rawPath){ return }

    # Remove quotes + expand env variables
    $expanded = _e ($rawPath -replace '"','')

    # Extract executable part only
    $exePath = $expanded.Split(" ")[0]

    if(!(Test-Path $exePath)){ return }

    # -------------------------------
    # Build folder chain
    # -------------------------------

    $parts = $exePath.Split("\")
    $acc   = ""
    $dirs  = @()

    foreach($p in $parts){

        $acc += "$p\"

        if(Test-Path $acc){
            $dirs += $acc
        }
    }

    $vulnerable = $false
    $vulnFolder = ""

    foreach($d in $dirs){

        $aclCheck = Get-Permissions $d

        if($aclCheck){

            foreach($perm in $aclCheck){
                if($perm.Writable){
                    $vulnerable = $true
                    $vulnFolder = $d
                    break
                }
            }
        }

        if($vulnerable){ break }
    }

    $fileAcl  = Get-Permissions $exePath
    $folderAcl = Get-Permissions (Split-Path $exePath -Parent)

    $r += [pscustomobject]@{
        Service          = $serviceName
        User             = $user
        Executable        = $exePath
        Vulnerable        = $vulnerable
        VulnerableFolder  = $vulnFolder
        Score             = _score $user $vulnerable
        FileACL           = ($fileAcl | ConvertTo-Json -Depth 3)
        FolderACL         = ($folderAcl | ConvertTo-Json -Depth 3)
    }

}

# ============================================================
# EXPORT TO DESKTOP
# ============================================================

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

try {
    $desktop = [Environment]::GetFolderPath("Desktop")

    if(!(Test-Path $desktop)){
        $desktop = $PWD.Path
    }
}
catch {
    $desktop = $PWD.Path
}

$csvFile = Join-Path $desktop "UnquotedServiceScan_$timestamp.csv"

$r |
Sort-Object Score -Descending |
Export-Csv -Path $csvFile -NoTypeInformation -Force

Write-Host ""
Write-Host "====================================="
Write-Host "Scan Complete"
Write-Host "Saved To: $csvFile"
Write-Host "====================================="
