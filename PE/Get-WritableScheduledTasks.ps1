<#
Deep Task + Process + DLL + Correlation Security Tool
Optimized Version
Author: 0xTr4c3
#>

param(
    [string] $ExportCsv = "",
    [string] $ExportJson = "",
    [switch] $VerboseMode,
    [int] $Threads = 20
)

function V($msg) { if ($VerboseMode) { Write-Host "[+] $msg" -ForegroundColor Cyan } }

function Expand-PathSafe([string]$p) {
    if (-not $p) { return $null }
    try { return [Environment]::ExpandEnvironmentVariables($p) }
    catch { return $p }
}

function Get-PathPermissions([string]$Path) {
    if (-not $Path -or -not (Test-Path $Path)) { return @() }
    try {
        $acl = Get-Acl -LiteralPath $Path
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        foreach ($ace in $acl.Access) {
            $allow = $ace.AccessControlType -eq 'Allow'
            $writable = $allow -and ($ace.FileSystemRights.ToString() -match 'Write|Modify|FullControl')
            $userMatch =
                $ace.IdentityReference.Value -eq $me -or
                $ace.IdentityReference.Value -match 'Everyone$|Users$|Authenticated Users$|BUILTIN\\Users'

            [PSCustomObject]@{
                Identity = $ace.IdentityReference.Value
                Rights   = $ace.FileSystemRights
                Type     = $ace.AccessControlType
                Writable = $writable -and $userMatch
            }
        }
    }
    catch { @() }
}

function Test-PathWritableByUser([string]$Path) {
    (Get-PathPermissions $Path | Where-Object { $_.Writable }) -ne $null
}

function Test-FolderWritable([string]$Path) {
    try {
        $folder = Split-Path $Path -Parent
        if (-not $folder) { return $false }
        return Test-PathWritableByUser $folder
    }
    catch { return $false }
}

function Get-AbuseScore {
    param([string]$User, [bool]$ExeWritable, [bool]$TaskFileWritable)

    $score = 0
    if ($User -match 'SYSTEM') { $score += 50 }
    elseif ($User -match 'Admin') { $score += 40 }
    elseif ($User) { $score += 10 }

    if ($ExeWritable) { $score += 20 }
    if ($TaskFileWritable) { $score += 15 }

    return $score
}

function Format-PermList($path) {
    (Get-PathPermissions $path |
        ForEach-Object { "$($_.Identity):$($_.Rights):$($_.Writable)" }
    ) -join ";"
}

# ------------------------------
# RESULTS STORAGE
# ------------------------------

$results = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::new()
$taskMap = @{}

# ===========================================================
# TASKS
# ===========================================================

V "Enumerating scheduled tasks..."

$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue

foreach ($task in $tasks) {

    $taskFull = "$($task.TaskPath)$($task.TaskName)"
    $taskMap[$taskFull.ToLower()] = @()

    try {
        $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath
        $last = $info.LastRunTime
        $next = $info.NextRunTime
    }
    catch {
        $last = ""
        $next = ""
    }

    foreach ($act in $task.Actions) {

        $exe = Expand-PathSafe $act.Execute
        if (-not $exe) { continue }

        $exeExists = Test-Path $exe
        $writableExe = Test-PathWritableByUser $exe
        $writableDir = Test-FolderWritable $exe

        $dlls = @()

        $taskFilePath =
            Join-Path (Join-Path $env:windir "System32\Tasks$($task.TaskPath)") $task.TaskName

        $taskFileWritable = Test-PathWritableByUser $taskFilePath

        $entry = [PSCustomObject]@{
            Source            = "ScheduledTask"
            Name              = $taskFull
            User              = $task.Principal.UserId
            RunLevel          = $task.Principal.RunLevel
            Execute           = $exe
            DLLs              = ($dlls -join ";")
            Exists            = $exeExists
            FileWritable      = $writableExe
            FolderWritable    = $writableDir
            FilePermissions   = Format-PermList $exe
            FolderPermissions  = Format-PermList (Split-Path $exe -Parent)
            TaskFilePath      = $taskFilePath
            TaskFileWritable  = $taskFileWritable
            Args              = $act.Arguments
            LastRun           = $last
            NextRun           = $next
            CorrelatedTasks   = ""
            AbuseScore        = Get-AbuseScore $task.Principal.UserId $writableExe $taskFileWritable
        }

        $results.Add($entry)
        $taskMap[$taskFull.ToLower()] += $exe
    }
}

# ===========================================================
# PROCESSES
# ===========================================================

V "Enumerating running processes..."

foreach ($proc in Get-Process -ErrorAction SilentlyContinue) {

    try { $path = $proc.Path } catch { continue }
    if (-not $path) { continue }
    if ($path -notmatch '\.(exe|dll)$') { continue }

    $writableExe = Test-PathWritableByUser $path
    $writableDir = Test-FolderWritable $path

    if (-not ($writableExe -or $writableDir)) { continue }

    try {
        $owner = (Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)").GetOwner().User
    }
    catch { $owner = "Unknown" }

    $results.Add([PSCustomObject]@{
        Source           = "Process"
        Name             = $proc.ProcessName
        User             = $owner
        RunLevel         = "RunningProcess"
        Execute          = $path
        DLLs             = ""
        Exists           = $true
        FileWritable     = $writableExe
        FolderWritable   = $writableDir
        FilePermissions  = Format-PermList $path
        FolderPermissions = Format-PermList (Split-Path $path -Parent)
        TaskFilePath     = ""
        TaskFileWritable  = $false
        Args             = ""
        LastRun          = ""
        NextRun          = ""
        CorrelatedTasks  = ""
        AbuseScore       = Get-AbuseScore $owner $writableExe $false
    })
}

# ===========================================================
# SERVICES
# ===========================================================

V "Enumerating services..."

foreach ($svc in Get-CimInstance Win32_Service) {

    $clean = ($svc.PathName -replace '"','').Split(" ")[0]
    if ($clean -notmatch '\.(exe|dll)$') { continue }

    $fileWritable = Test-PathWritableByUser $clean
    $folderWritable = Test-FolderWritable $clean

    if (-not ($fileWritable -or $folderWritable)) { continue }

    $results.Add([PSCustomObject]@{
        Source           = "Service"
        Name             = $svc.Name
        User             = $svc.StartName
        RunLevel         = "ServiceContext"
        Execute          = $clean
        DLLs             = ""
        Exists           = Test-Path $clean
        FileWritable     = $fileWritable
        FolderWritable   = $folderWritable
        FilePermissions  = Format-PermList $clean
        FolderPermissions = Format-PermList (Split-Path $clean -Parent)
        TaskFilePath     = ""
        TaskFileWritable  = $false
        Args             = $svc.PathName
        LastRun          = ""
        NextRun          = ""
        CorrelatedTasks  = ""
        AbuseScore       = Get-AbuseScore $svc.StartName $fileWritable $false
    })
}

# ===========================================================
# GLOBAL SCAN (OPTIMIZED + FIXED PARALLEL)
# ===========================================================

V "Scanning drives for .exe/.dll ..."

$drives = Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Root

$filesToScan = foreach ($drv in $drives) {
    Get-ChildItem -Path $drv -Include *.exe,*.dll -Recurse -Force -ErrorAction SilentlyContinue
}

$filesToScan |
ForEach-Object -Parallel {

    param($results)

    function Test-PathWritableByUser([string]$Path) {
        try {
            $acl = Get-Acl -LiteralPath $Path
            $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            foreach ($ace in $acl.Access) {
                if ($ace.IdentityReference.Value -match 'Everyone|Users|Authenticated') {
                    if ($ace.FileSystemRights.ToString() -match 'Write|Modify|FullControl') {
                        return $true
                    }
                }
            }
        } catch {}
        return $false
    }

    function Test-FolderWritable([string]$Path) {
        return Test-PathWritableByUser (Split-Path $Path -Parent)
    }

    try {
        $wFile = Test-PathWritableByUser $_.FullName
        $wFolder = Test-FolderWritable $_.FullName

        if ($wFile -or $wFolder) {

            $entry = [PSCustomObject]@{
                Source          = "GlobalScan"
                Name            = $_.Name
                User            = ""
                RunLevel        = ""
                Execute         = $_.FullName
                DLLs            = ""
                Exists          = $true
                FileWritable    = $wFile
                FolderWritable  = $wFolder
                FilePermissions = ""
                FolderPermissions = ""
                TaskFilePath    = ""
                TaskFileWritable = $false
                Args            = ""
                LastRun         = ""
                NextRun         = ""
                CorrelatedTasks = ""
                AbuseScore      = 0
            }

            $results.Add($entry)
        }
    }
    catch {}

} -ArgumentList $results -ThrottleLimit $Threads

# ===========================================================
# EXPORT
# ===========================================================

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvFile = if ($ExportCsv) { $ExportCsv } else { "DeepTaskAudit_$timestamp.csv" }

$results.ToArray() | Export-Csv -Path $csvFile -NoTypeInformation -Force
Write-Host "CSV → $csvFile"

if ($ExportJson) {
    $results.ToArray() | ConvertTo-Json -Depth 6 | Out-File $ExportJson -Force
    Write-Host "JSON → $ExportJson"
}

$results.ToArray() |
Sort-Object AbuseScore -Descending |
Format-Table Source,Name,Execute,FileWritable,FolderWritable,User,AbuseScore -AutoSize
