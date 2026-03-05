<#
Unquoted Service Path Auditor
---------------------------------------------

Detects services that:

1. Run with elevated privileges
2. Have unquoted executable paths
3. Contain spaces in the path
4. AND where the current user can write to a directory in the path

Author: Security Audit Script
#>

param(
    [switch]$VerboseMode,
    [string]$ExportCsv = ""
)

function V($m){
    if($VerboseMode){ Write-Host "[+] $m" -ForegroundColor Cyan }
}

function Expand-Path($p){
    if(!$p){ return $null }
    return [Environment]::ExpandEnvironmentVariables($p)
}

function Test-DirectoryWritable($Path){

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

function Get-AbuseScore($svcUser,$writable){

    $score = 0

    if($svcUser -match "SYSTEM"){ $score += 50 }
    if($svcUser -match "LocalSystem"){ $score += 50 }
    if($writable){ $score += 40 }

    return $score
}

$results = @()

V "Scanning services..."

Get-CimInstance Win32_Service | ForEach-Object {

    $serviceName = $_.Name
    $startName   = $_.StartName
    $rawPath     = $_.PathName

    if(!$rawPath){ return }

    # Remove quotes
    $cleanPath = $rawPath -replace '"',''

    # Check if path is unquoted
    $isQuoted = ($rawPath -match '^"')

    # We only care if:
    # - Elevated service
    # - Path contains spaces
    # - Not quoted
    if(
        $startName -notmatch "LocalSystem|SYSTEM" -and
        $startName -notmatch "Admin"
    ){
        return
    }

    if($isQuoted){ return }

    if($cleanPath -notmatch "\s"){ return }

    # Split to detect directory chain
    $parts = $cleanPath.Split(" ")

    $potentialDirs = @()

    # Build incremental path checks
    $accumulator = ""
    foreach($p in $cleanPath.Split("\")){

        $accumulator += "$p\"

        if(Test-Path $accumulator){
            $potentialDirs += $accumulator
        }
    }

    $writable = $false

    foreach($dir in $potentialDirs){

        if(Test-DirectoryWritable $dir){
            $writable = $true
            break
        }
    }

    if(!$writable){ return }

    $results += [PSCustomObject]@{

        Source="UnquotedServicePath"
        Service=$serviceName
        User=$startName
        RawPath=$rawPath
        CleanPath=$cleanPath
        WritablePath=$writable
        AbuseScore=Get-AbuseScore $startName $writable
    }

}

$results = $results | Sort-Object AbuseScore -Descending

$results | Format-Table -AutoSize

if($ExportCsv){
    $results | Export-Csv $ExportCsv -NoTypeInformation
    Write-Host "CSV Exported -> $ExportCsv"
}
