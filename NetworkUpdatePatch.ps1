



Clear-Host
Write-Host "===== ULTRA STEALTH TOPOLOGY INTELLIGENCE ENGINE v9 =====" -ForegroundColor Cyan
Write-Host ""





function Get-SubnetFromIP {
    param($6FZI6TC2gRzj9RjVbTgF,$fTppkXnjFwbJsU3h9zWjgf = 24)

    if ($6FZI6TC2gRzj9RjVbTgF -match "^\d+\.\d+\.\d+\.\d+$") {

        $ONvhilpWT = $6FZI6TC2gRzj9RjVbTgF.Split(".")

        if ($fTppkXnjFwbJsU3h9zWjgf -ge 24) {
            return "$($ONvhilpWT[0]).$($ONvhilpWT[1]).$($ONvhilpWT[2]).0/24"
        }
        elseif ($fTppkXnjFwbJsU3h9zWjgf -ge 16) {
            return "$($ONvhilpWT[0]).$($ONvhilpWT[1]).0.0/16"
        }
        else {
            return "$($ONvhilpWT[0]).0.0.0/$fTppkXnjFwbJsU3h9zWjgf"
        }
    }

    return $null
}

function Clean-Net {
    param($Xs1GwK)

    if ($Xs1GwK -and $Xs1GwK -notmatch "^0\.|^127\.|^224\.|^240\.|^255\.") {
        return $Xs1GwK
    }

    return $null
}

function Test-FastPort {
    param($6FZI6TC2gRzj9RjVbTgF,$jKe0PVcTZE4tkiWRNxQAlHJ6C)

    try {
        $iWoZ7VtXlhC = New-Object System.Net.Sockets.TcpClient
        $nqO1uvSZ0m = $iWoZ7VtXlhC.BeginConnect($6FZI6TC2gRzj9RjVbTgF,$jKe0PVcTZE4tkiWRNxQAlHJ6C,$null,$null)
        $R0WEQ1M = $nqO1uvSZ0m.AsyncWaitHandle.WaitOne(80,$false)

        if ($R0WEQ1M -and $iWoZ7VtXlhC.Connected) {
            $iWoZ7VtXlhC.Close()
            return $true
        }

        $iWoZ7VtXlhC.Close()
    }
    catch {}

    return $false
}

function Test-FastPing {
    param($6FZI6TC2gRzj9RjVbTgF)

    try {
        $rOoVqz9K1iQ742 = New-Object System.Net.NetworkInformation.Ping
        $PaUw859Bj = $rOoVqz9K1iQ742.Send($6FZI6TC2gRzj9RjVbTgF,100)

        if ($PaUw859Bj.Status -eq "Success") {
            return $true
        }
    }
    catch {}

    return $false
}





$qgRpLXk3mvVPfnJT96 = @()
$z7KRjB4No   = @()
$CpIrWR3iMs = @()

Write-Host "[+] Collecting Interfaces..."
Get-NetIPConfiguration | ForEach-Object {
    if ($_.IPv4Address.IPAddress) {

        $Xs1GwK = Get-SubnetFromIP $_.IPv4Address.IPAddress $_.IPv4Address.PrefixLength
        $Xs1GwK = Clean-Net $Xs1GwK
        if ($Xs1GwK) { $qgRpLXk3mvVPfnJT96 += $Xs1GwK }
    }
}

Write-Host "[+] Collecting Routing Table..."
Get-NetRoute -AddressFamily IPv4 |
Where-Object { $_.DestinationPrefix -match "/" } |
ForEach-Object {

    $ts1xQvSUpb0NoBl6 = ($_.DestinationPrefix -split "/")[0]
    $fTppkXnjFwbJsU3h9zWjgf = ($_.DestinationPrefix -split "/")[1]

    $Xs1GwK = Get-SubnetFromIP $ts1xQvSUpb0NoBl6 $fTppkXnjFwbJsU3h9zWjgf
    $Xs1GwK = Clean-Net $Xs1GwK
    if ($Xs1GwK) { $qgRpLXk3mvVPfnJT96 += $Xs1GwK }
}

Write-Host "[+] Collecting ARP..."
$z7KRjB4No = Get-NetNeighbor |
Where-Object { $_.State -ne "Unreachable" -and $_.IPAddress -match "^\d+\." } |
Select-Object -ExpandProperty IPAddress -Unique

foreach ($6FZI6TC2gRzj9RjVbTgF in $z7KRjB4No) {
    $ONvhilpWT = $6FZI6TC2gRzj9RjVbTgF.Split(".")
    $Xs1GwK = "$($ONvhilpWT[0]).$($ONvhilpWT[1]).$($ONvhilpWT[2]).0/24"
    $Xs1GwK = Clean-Net $Xs1GwK
    if ($Xs1GwK) { $qgRpLXk3mvVPfnJT96 += $Xs1GwK }
}

Write-Host "[+] Discovering Infrastructure Services..."


try {
    $gbPVqCY = Get-DnsClientServerAddress -AddressFamily IPv4 |
                  Select-Object -ExpandProperty ServerAddresses -Unique

    foreach ($5OIbCPHlD7L3wYjSErmqhdZ in $gbPVqCY) {
        if ($5OIbCPHlD7L3wYjSErmqhdZ -match "^\d+\.\d+\.\d+\.\d+$") {
            $CpIrWR3iMs += $5OIbCPHlD7L3wYjSErmqhdZ
        }
    }
}
catch {}


try {
    $VaRO61ISDD9YVxKvR2xSfZEd = Get-ADDomainController -ErrorAction SilentlyContinue
    foreach ($OdlnWCJj3gR5K in $VaRO61ISDD9YVxKvR2xSfZEd) {
        if ($OdlnWCJj3gR5K.IPv4Address) {
            $CpIrWR3iMs += $OdlnWCJj3gR5K.IPv4Address
        }
    }
}
catch {}


try {
    $4jW0YzPS1hGoq57 = Get-DhcpServerInDC -ErrorAction SilentlyContinue
    foreach ($4RxQC75dl6 in $4jW0YzPS1hGoq57) {
        if ($4RxQC75dl6.IPAddress) {
            $CpIrWR3iMs += $4RxQC75dl6.IPAddress
        }
    }
}
catch {}


try {
    $84Ui = Get-SmbSession -ErrorAction SilentlyContinue
    foreach ($hq2NMzG in $84Ui) {
        if ($hq2NMzG.ClientComputerName -match "^\d+\.\d+\.\d+\.\d+$") {
            $CpIrWR3iMs += $hq2NMzG.ClientComputerName
        }
    }
}
catch {}


foreach ($6FZI6TC2gRzj9RjVbTgF in $CpIrWR3iMs) {
    $ONvhilpWT = $6FZI6TC2gRzj9RjVbTgF.Split(".")
    $qgRpLXk3mvVPfnJT96 += "$($ONvhilpWT[0]).$($ONvhilpWT[1]).$($ONvhilpWT[2]).0/24"
}

$qgRpLXk3mvVPfnJT96 = $qgRpLXk3mvVPfnJT96 | Sort-Object -Unique

Write-Host ""
Write-Host "Discovered Networks: $($qgRpLXk3mvVPfnJT96.Count)"
Write-Host ""





Write-Host "[+] Performing Smart Reachability Analysis..."

$wi7BT9 = @()

foreach ($Xs1GwK in $qgRpLXk3mvVPfnJT96) {

    $ts1xQvSUpb0NoBl6 = ($Xs1GwK -split "/")[0]
    $ONvhilpWT = $ts1xQvSUpb0NoBl6.Split(".")
    if ($ONvhilpWT.Count -lt 3) { continue }

    $blEtFZxuU3aweBHrWLcDY = "$($ONvhilpWT[0]).$($ONvhilpWT[1]).$($ONvhilpWT[2])"

    $ng4JufVIorhBCxt7v = 0

    
    if ($z7KRjB4No | Where-Object { $_ -like "$blEtFZxuU3aweBHrWLcDY.*" }) { $ng4JufVIorhBCxt7v += 3 }
    if ($CpIrWR3iMs | Where-Object { $_ -like "$blEtFZxuU3aweBHrWLcDY.*" }) { $ng4JufVIorhBCxt7v += 3 }

    
    $Slvq = Get-NetRoute -DestinationPrefix "0.0.0.0/0" |
               Select-Object -First 1 -ExpandProperty NextHop -ErrorAction SilentlyContinue

    if ($Slvq -like "$blEtFZxuU3aweBHrWLcDY.*") { $ng4JufVIorhBCxt7v += 1 }

    
    if ($ng4JufVIorhBCxt7v -lt 3) {

        $zQUNnDujagavA5 = "$blEtFZxuU3aweBHrWLcDY.1"
        $heH = "$blEtFZxuU3aweBHrWLcDY.254"
        $gm8AHl0z  = "$blEtFZxuU3aweBHrWLcDY.$(Get-Random -Minimum 2 -Maximum 200)"

        if (Test-FastPing $zQUNnDujagavA5) { $ng4JufVIorhBCxt7v++ }
        elseif (Test-FastPing $heH) { $ng4JufVIorhBCxt7v++ }
        elseif (Test-FastPing $gm8AHl0z) { $ng4JufVIorhBCxt7v++ }
    }

    
    foreach ($jKe0PVcTZE4tkiWRNxQAlHJ6C in @(53,88,389,445)) {
        if (Test-FastPort "$blEtFZxuU3aweBHrWLcDY.1" $jKe0PVcTZE4tkiWRNxQAlHJ6C) { $ng4JufVIorhBCxt7v++ }
    }

    if ($ng4JufVIorhBCxt7v -ge 2) {
        Write-Host "[+] ACTIVE -> $blEtFZxuU3aweBHrWLcDY.0/24 (Score:$ng4JufVIorhBCxt7v)" -ForegroundColor Cyan
        $wi7BT9 += "$blEtFZxuU3aweBHrWLcDY.0/24"
    }
}

$wi7BT9 = $wi7BT9 | Sort-Object -Unique





Write-Host ""
Write-Host "========================================="
Write-Host "FINAL RESULTS"
Write-Host "========================================="
Write-Host ""
Write-Host "Active Networks:"

if ($wi7BT9.Count -eq 0) {
    Write-Host " -> None detected"
}
else {
    $wi7BT9 | ForEach-Object { Write-Host " -> $_" }
}

Write-Host ""
Write-Host "Done."


