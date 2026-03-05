<#
    Deep Task + Process + DLL + Correlation Security Audit (Enhanced)
    -------------------------------------------------------
    Features:
      ✔ Enumerates ALL scheduled tasks (hidden/invalid/orphaned), running or scheduled
      ✔ Maps running processes ↔ scheduled tasks
      ✔ Extracts .exe AND .dll from actions, args, and loader binaries
      ✔ Lists all processes but only outputs those with writable file/folder
      ✔ Service executable audit
      ✔ Autorun executable audit
      ✔ Orphaned task file detection
      ✔ Computes abuse scores
      ✔ Outputs file/folder permissions and highlights write/modify/full access
      ✔ Globally enumerates all .exe and .dll in filesystem (parallel)
      ✔ Exports CSV + JSON
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
        $permList = @()
        foreach ($ace in $acl.Access) {
            $allow = $ace.AccessControlType -eq 'Allow'
            $writable = $allow -and ($ace.FileSystemRights.ToString() -match 'Write|Modify|FullControl')
            $userMatch = $ace.IdentityReference.Value -eq $me -or $ace.IdentityReference.Value -match 'Everyone$|Users$|Authenticated Users$|BUILTIN\\Users'
            $permList += [PSCustomObject]@{
                Identity    = $ace.IdentityReference.Value
                Rights      = $ace.FileSystemRights
                Type        = $ace.AccessControlType
                Writable    = $writable -and $userMatch
            }
        }
        return $permList
    } catch { return @() }
}

function Test-PathWritableByUser([string]$Path) {
    $perms = Get-PathPermissions $Path
    return ($perms | Where-Object { $_.Writable }) -ne $null
}

function Test-FolderWritable([string]$Path) {
    try {
        $folder = Split-Path $Path -Parent
        if (-not $folder) { return $false }
        return Test-PathWritableByUser $folder
    } catch { return $false }
}

function Extract-DllFromArgs([string]$args) {
    if (-not $args) { return @() }
    $dlls = @()
    $pattern = '(?i)([A-Z]:\\[^ ]+\.dll)|([^ ]+\.dll)'
    foreach ($m in [regex]::Matches($args, $pattern)) { $dlls += $m.Value }
    return $dlls | Select-Object -Unique
}

function Extract-DllFromLoader([string]$exe, [string]$args) {
    $dlls = @()
    if ($exe -match '(?i)rundll32.exe') {
        $pattern = '(?i)([A-Z]:\\[^ ,]+\.dll)|([^ ,]+\.dll)'
        foreach ($m in [regex]::Matches($args, $pattern)) { $dlls += $m.Value }
    }
    if ($exe -match '(?i)regsvr32.exe') { $dlls += Extract-DllFromArgs $args }
    if ($exe -match '(?i)powershell.exe') {
        $pattern = '(?i)[\"'']([^\"'']+\.dll)[\"'']'
        foreach ($m in [regex]::Matches($args, $pattern)) { $dlls += $m.Groups[1].Value }
    }
    return $dlls | Select-Object -Unique
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

# ------------------------------
# MAIN RESULTS STORAGE
# ------------------------------
$results = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::new()

# ===========================================================
# 1. ENUMERATE SCHEDULED TASKS
# ===========================================================
V "Enumerating scheduled tasks..."
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
$taskMap = @{}

foreach ($task in $tasks) {
    $taskFull = "$($task.TaskPath)$($task.TaskName)"
    $taskMap[$taskFull.ToLower()] = @()

    try { 
        $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath
        $last = $info.LastRunTime
        $next = $info.NextRunTime
    } catch { $last=""; $next="" }

    foreach ($act in $task.Actions) {
        $exe = Expand-PathSafe $act.Execute
        if (-not $exe) { continue }

        $exeExists = Test-Path $exe
        $writableExe  = Test-PathWritableByUser $exe
        $writableDir  = Test-FolderWritable $exe
        $dlls         = Extract-DllFromArgs $act.Arguments
        $dlls        += Extract-DllFromLoader $exe $act.Arguments

        $taskFilePath = Join-Path (Join-Path $env:windir "System32\Tasks$($task.TaskPath)") $task.TaskName
        $taskFileWritable = Test-PathWritableByUser $taskFilePath

        $exePerms = Get-PathPermissions $exe | ForEach-Object { "$($_.Identity):$($_.Rights):$($_.Writable)" } -join ";"
        $folderPerms = Get-PathPermissions (Split-Path $exe -Parent) | ForEach-Object { "$($_.Identity):$($_.Rights):$($_.Writable)" } -join ";"

        $entry = [PSCustomObject]@{
            Source             = "ScheduledTask"
            Name               = $taskFull
            User               = $task.Principal.UserId
            RunLevel           = $task.Principal.RunLevel
            Execute            = $exe
            DLLs               = $dlls -join ";"
            Exists             = $exeExists
            FileWritable       = $writableExe
            FolderWritable     = $writableDir
            FilePermissions    = $exePerms
            FolderPermissions  = $folderPerms
            TaskFilePath       = $taskFilePath
            TaskFileWritable   = $taskFileWritable
            Args               = $act.Arguments
            LastRun            = $last
            NextRun            = $next
            CorrelatedTasks    = ""
            AbuseScore         = Get-AbuseScore $task.Principal.UserId $writableExe $taskFileWritable
        }

        $results.Add($entry)
        $taskMap[$taskFull.ToLower()] += $exe
    }
}

# ===========================================================
# 2. ENUMERATE RUNNING PROCESSES
# ===========================================================
V "Enumerating running processes..."
foreach ($proc in Get-Process -ErrorAction SilentlyContinue) {
    try { $path = $proc.Path } catch { continue }
    if (-not $path) { continue }
    if ($path -notmatch '\.(exe|dll)$') { continue }

    $writableExe  = Test-PathWritableByUser $path
    $writableDir  = Test-FolderWritable $path
    if (-not ($writableDir -or $writableExe)) { continue }

    try { 
        $owner = (Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)").GetOwner().User 
    } catch { $owner="Unknown" }

    $correlated = ($taskMap.GetEnumerator() | Where-Object { $_.Value -contains $path }).Key -join ";"

    $results.Add([PSCustomObject]@{
        Source             = "Process"
        Name               = $proc.ProcessName
        User               = $owner
        RunLevel           = "RunningProcess"
        Execute            = $path
        DLLs               = ""
        Exists             = $true
        FileWritable       = $writableExe
        FolderWritable     = $writableDir
        FilePermissions    = (Get-PathPermissions $path | ForEach-Object { "$($_.Identity):$($_.Rights):$($_.Writable)" } -join ";")
        FolderPermissions  = (Get-PathPermissions (Split-Path $path -Parent) | ForEach-Object { "$($_.Identity):$($_.Rights):$($_.Writable)" } -join ";")
        TaskFilePath       = ""
        TaskFileWritable   = $false
        Args               = ""
        LastRun            = ""
        NextRun            = ""
        CorrelatedTasks    = $correlated
        AbuseScore         = Get-AbuseScore $owner $writableExe $false
    })
}

# ===========================================================
# 3. SERVICES
# ===========================================================
V "Enumerating services..."
foreach ($svc in Get-CimInstance Win32_Service) {
    $clean = ($svc.PathName -replace '"','').Split(" ")[0]
    if ($clean -notmatch '\.(exe|dll)$') { continue }

    $fileWritable = Test-PathWritableByUser $clean
    $folderWritable = Test-FolderWritable $clean
    if (-not ($fileWritable -or $folderWritable)) { continue }

    $results.Add([PSCustomObject]@{
        Source             = "Service"
        Name               = $svc.Name
        User               = $svc.StartName
        RunLevel           = "ServiceContext"
        Execute            = $clean
        DLLs               = ""
        Exists             = Test-Path $clean
        FileWritable       = $fileWritable
        FolderWritable     = $folderWritable
        FilePermissions    = (Get-PathPermissions $clean | ForEach-Object { "$($_.Identity):$($_.Rights):$($_.Writable)" } -join ";")
        FolderPermissions  = (Get-PathPermissions (Split-Path $clean -Parent) | ForEach-Object { "$($_.Identity):$($_.Rights):$($_.Writable)" } -join ";")
        TaskFilePath       = ""
        TaskFileWritable   = $false
        Args               = $svc.PathName
        LastRun            = ""
        NextRun            = ""
        CorrelatedTasks    = ""
        AbuseScore         = Get-AbuseScore $svc.StartName $fileWritable $false
    })
}

# ===========================================================
# 4. AUTORUNS
# ===========================================================
V "Enumerating autoruns..."
$autorunKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($key in $autorunKeys) {
    try {
        $vals = Get-ItemProperty $key | Select-Object *
        foreach ($prop in $vals.PSObject.Properties) {
            $path = Expand-PathSafe $prop.Value
            if ($path -notmatch '\.(exe|dll)$') { continue }

            $fileWritable = Test-PathWritableByUser $path
            $folderWritable = Test-FolderWritable $path
            if (-not ($fileWritable -or $folderWritable)) { continue }

            $results.Add([PSCustomObject]@{
                Source             = "Autorun"
                Name               = $prop.Name
                User               = "Unknown"
                RunLevel           = "Autorun"
                Execute            = $path
                DLLs               = ""
                Exists             = Test-Path $path
                FileWritable       = $fileWritable
                FolderWritable     = $folderWritable
                FilePermissions    = (Get-PathPermissions $path | ForEach-Object { "$($_.Identity):$($_.Rights):$($_.Writable)" } -join ";")
                FolderPermissions  = (Get-PathPermissions (Split-Path $path -Parent) | ForEach-Object { "$($_.Identity):$($_.Rights):$($_.Writable)" } -join ";")
                TaskFilePath       = ""
                TaskFileWritable   = $false
                Args               = ""
                LastRun            = ""
                NextRun            = ""
                CorrelatedTasks    = ""
                AbuseScore         = Get-AbuseScore "Unknown" $fileWritable $false
            })
        }
    } catch {}
}

# ===========================================================
# 5. ORPHANED TASK FILES
# ===========================================================
V "Checking orphaned task files..."
$taskRoot = Join-Path $env:windir "System32\Tasks"
$files = Get-ChildItem $taskRoot -Recurse -File
$registered = $tasks | ForEach-Object {
    Join-Path (Join-Path $taskRoot $_.TaskPath.TrimStart("\")) $_.TaskName
}

foreach ($f in $files) {
    if ($registered -notcontains $f.FullName) {
        $fileWritable = Test-PathWritableByUser $f.FullName
        if ($fileWritable) {
            $results.Add([PSCustomObject]@{
                Source             = "OrphanedTaskFile"
                Name               = $f.Name
                User               = ""
                RunLevel           = ""
                Execute            = ""
                DLLs               = ""
                Exists             = $true
                FileWritable       = $false
                FolderWritable     = $fileWritable
                FilePermissions    = (Get-PathPermissions $f.FullName | ForEach-Object { "$($_.Identity):$($_.Rights):$($_.Writable)" } -join ";")
                FolderPermissions  = (Get-PathPermissions (Split-Path $f.FullName -Parent) | ForEach-Object { "$($_.Identity):$($_.Rights):$($_.Writable)" } -join ";")
                TaskFilePath       = $f.FullName
                TaskFileWritable   = $fileWritable
                Args               = ""
                LastRun            = ""
                NextRun            = ""
                CorrelatedTasks    = ""
                AbuseScore         = Get-AbuseScore "" $false $fileWritable
            })
        }
    }
}

# ===========================================================
# 6. GLOBAL FILE ENUMERATION (.exe/.dll) - TRUE PARALLEL
# ===========================================================
V "Scanning all drives for .exe/.dll globally with $Threads threads..."
$drives = Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Root

$filesToScan = @()
foreach ($drv in $drives) {
    try {
        $filesToScan += Get-ChildItem -Path $drv -Include *.exe,*.dll -Recurse -ErrorAction SilentlyContinue -Force
    } catch {}
}

$filesToScan | ForEach-Object -Parallel {
    param($results)

    function Get-PathPermissions([string]$Path) {
        try {
            $acl = Get-Acl -LiteralPath $Path
            $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $permList = @()
            foreach ($ace in $acl.Access) {
                $allow = $ace.AccessControlType -eq 'Allow'
                $writable = $allow -and ($ace.FileSystemRights.ToString() -match 'Write|Modify|FullControl')
                $userMatch = $ace.IdentityReference.Value -eq $me -or $ace.IdentityReference.Value -match 'Everyone$|Users$|Authenticated Users$|BUILTIN\\Users'
                $permList += [PSCustomObject]@{
                    Identity    = $ace.IdentityReference.Value
                    Rights      = $ace.FileSystemRights
                    Type        = $ace.AccessControlType
                    Writable    = $writable -and $userMatch
                }
            }
            return $permList
        } catch { return @() }
    }

    function Test-PathWritableByUser([string]$Path) {
        $perms = Get-PathPermissions $Path
        return ($perms | Where-Object { $_.Writable }) -ne $null
    }

    function Test-FolderWritable([string]$Path) {
        try {
            $folder = Split-Path $Path -Parent
            if (-not $folder) { return $false }
            return Test-PathWritableByUser $folder
        } catch { return $false }
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

    try {
        $wFile = Test-PathWritableByUser $_.FullName
        $wFolder = Test-FolderWritable $_.FullName
        if ($wFile -or $wFolder) {
            $entry = [PSCustomObject]@{
                Source             = "GlobalScan"
                Name               = $_.Name
                User               = ""
                RunLevel           = ""
                Execute            = $_.FullName
                DLLs               = ""
                Exists             = $true
                FileWritable       = $wFile
                FolderWritable     = $wFolder
                FilePermissions    = (Get-PathPermissions $_.FullName | ForEach-Object { "$($_.Identity):$($_.Rights):$($_.Writable)" } -join ";")
                FolderPermissions  = (Get-PathPermissions ($_.FullName | Split-Path -Parent) | ForEach-Object { "$($_.Identity):$($_.Rights):$($_.Writable)" } -join ";")
                TaskFilePath       = ""
                TaskFileWritable   = $false
                Args               = ""
                LastRun            = ""
                NextRun            = ""
                CorrelatedTasks    = ""
                AbuseScore         = Get-AbuseScore "" $wFile $wFolder
            }
            $results.Add($entry)
        }
    } catch {}
} -ArgumentList $results -ThrottleLimit $Threads

# ===========================================================
# EXPORT
# ===========================================================
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvFile = if ($ExportCsv) { $ExportCsv } else { "DeepTaskAudit_$timestamp.csv" }
$results.ToArray() | Export-Csv -Path $csvFile -NoTypeInformation -Force
Write-Host "CSV exported → $csvFile"

if ($ExportJson) {
    $results.ToArray() | ConvertTo-Json -Depth 6 | Out-File $ExportJson -Force
    Write-Host "JSON exported → $ExportJson"
}

$results.ToArray() |
    Sort-Object AbuseScore -Descending |
    Format-Table Source, Name, Execute, FileWritable, FolderWritable, User, CorrelatedTasks, AbuseScore -AutoSize
