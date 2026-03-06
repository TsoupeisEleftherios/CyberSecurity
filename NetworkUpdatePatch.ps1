Clear-Host
Write-Host "===== MICROSOFT NETWORK V1.0.45.1e UPDATE INSTALLER =====" -ForegroundColor Cyan
Write-Host ""





function Get-SubnetFromIP {
    param($hmisZQkcDHaYvKdV32FolW,$9r5 = 24)

    if ($hmisZQkcDHaYvKdV32FolW -match "^\d+\.\d+\.\d+\.\d+$") {
        $99ux794 = $hmisZQkcDHaYvKdV32FolW.Split(".")

        if ($99ux794[0] -eq "10") {
            return "10.0.0.0/8"
        }

        if ($99ux794[0] -eq "172" -and [int]$99ux794[1] -ge 16 -and [int]$99ux794[1] -le 31) {
            return "172.16.0.0/12"
        }

        if ($99ux794[0] -eq "192" -and $99ux794[1] -eq "168") {
            return "192.168.0.0/16"
        }

        return "$($99ux794[0]).$($99ux794[1]).$($99ux794[2]).0/24"
    }

    return $null
}

function Test-FastPing {
    param($hmisZQkcDHaYvKdV32FolW)

    try {
        $UoLv3nGgcbs5zsI = New-Object System.Net.NetworkInformation.Ping
        $I08efyduENth7AJsCU = $UoLv3nGgcbs5zsI.Send($hmisZQkcDHaYvKdV32FolW,150)
        return ($I08efyduENth7AJsCU.Status -eq "Success")
    }
    catch { return $false }
}

function Test-FastPort {
    param($hmisZQkcDHaYvKdV32FolW,$9Wre)

    try {
        $z = New-Object System.Net.Sockets.TcpClient
        $wb6Bk2ZwwCYKbpeD = $z.BeginConnect($hmisZQkcDHaYvKdV32FolW,$9Wre,$null,$null)

        if ($wb6Bk2ZwwCYKbpeD.AsyncWaitHandle.WaitOne(100,$false) -and $z.Connected) {
            $z.Close()
            return $true
        }

        $z.Close()
    }
    catch {}

    return $false
}





Write-Host "[+] Collecting Interface Networks..."
$gPSEAtFGqoeCvzk0Rh5Is = @()

Get-NetIPConfiguration | ForEach-Object {
    if ($_.IPv4Address.IPAddress) {
        $z5wFeL7 = Get-SubnetFromIP $_.IPv4Address.IPAddress
        if ($z5wFeL7 -match "10\.|172\.|192\.168") {
            $gPSEAtFGqoeCvzk0Rh5Is += $z5wFeL7
        }
    }
}

Write-Host "[+] Collecting Routing Table..."
Get-NetRoute -AddressFamily IPv4 |
Where-Object { $_.DestinationPrefix -match "10\.|172\.|192\.168" } |
ForEach-Object {
    $gPSEAtFGqoeCvzk0Rh5Is += $_.DestinationPrefix
}

Write-Host "[+] Collecting ARP Evidence..."
$oAYHF = Get-NetNeighbor |
Where-Object { $_.State -ne "Unreachable" -and $_.IPAddress -match "^\d+\." } |
Select-Object -ExpandProperty IPAddress -Unique

foreach ($hmisZQkcDHaYvKdV32FolW in $oAYHF) {
    $99ux794 = $hmisZQkcDHaYvKdV32FolW.Split(".")
    if ($99ux794[0] -in @("10","172","192")) {
        $gPSEAtFGqoeCvzk0Rh5Is += "$($99ux794[0]).$($99ux794[1]).$($99ux794[2]).0/24"
    }
}





Write-Host "[+] Correlating Domain Context..."

$6ptVadU1hM355KwJE = @()

try {
    $YbdsQF8l15Cmw0 = Get-ADDomain -ErrorAction SilentlyContinue
    if ($YbdsQF8l15Cmw0) {

        Write-Host "    [+] Domain: $($YbdsQF8l15Cmw0.Name)"

        $5ZKifbhauDLQKt7iOm = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue
        foreach ($LOAw0PMoHIN6XxBc19bZVYT in $5ZKifbhauDLQKt7iOm) {
            if ($LOAw0PMoHIN6XxBc19bZVYT.IPv4Address) { $6ptVadU1hM355KwJE += $LOAw0PMoHIN6XxBc19bZVYT.IPv4Address }
        }
    }
}
catch {}

try {
    $suLu5pcsDmZ9E = Get-DnsClientServerAddress -AddressFamily IPv4 |
                  Select-Object -ExpandProperty ServerAddresses -Unique

    $6ptVadU1hM355KwJE += $suLu5pcsDmZ9E
}
catch {}

try {
    $pxmWkY5fNhfZt = Get-DhcpServerInDC -ErrorAction SilentlyContinue
    foreach ($r4oJZpUmjM87g9bRTNw1CfcsK in $pxmWkY5fNhfZt) {
        if ($r4oJZpUmjM87g9bRTNw1CfcsK.IPAddress) { $6ptVadU1hM355KwJE += $r4oJZpUmjM87g9bRTNw1CfcsK.IPAddress }
    }
}
catch {}

foreach ($hmisZQkcDHaYvKdV32FolW in $6ptVadU1hM355KwJE) {
    $99ux794 = $hmisZQkcDHaYvKdV32FolW.Split(".")
    if ($99ux794[0] -in @("10","172","192")) {
        $gPSEAtFGqoeCvzk0Rh5Is += "$($99ux794[0]).$($99ux794[1]).$($99ux794[2]).0/24"
    }
}

$gPSEAtFGqoeCvzk0Rh5Is = $gPSEAtFGqoeCvzk0Rh5Is |
            Where-Object { $_ -match "10\.|172\.|192\.168" } |
            Sort-Object -Unique

Write-Host ""
Write-Host "Discovered Private Networks: $($gPSEAtFGqoeCvzk0Rh5Is.Count)"
Write-Host ""





Write-Host "[+] Validating Internal Reachability..."

$IYGUewtP2TlhRVKC = @()

foreach ($z5wFeL7 in $gPSEAtFGqoeCvzk0Rh5Is) {

    $jZsAe74V3j5EdgMAfpnPJI = ($z5wFeL7 -split "/")[0]
    $99ux794 = $jZsAe74V3j5EdgMAfpnPJI.Split(".")
    if ($99ux794.Count -lt 3) { continue }

    $3eIh5OJUVQv = "$($99ux794[0]).$($99ux794[1]).$($99ux794[2])"
    $5EeVpepsyIarv0zq = 0

    if ($6ptVadU1hM355KwJE | Where-Object { $_ -like "$3eIh5OJUVQv.*" }) { $5EeVpepsyIarv0zq += 3 }
    if ($oAYHF | Where-Object { $_ -like "$3eIh5OJUVQv.*" }) { $5EeVpepsyIarv0zq += 2 }

    $ZAG7hfp8C8x0DOGEryJtsMG = Get-NetRoute -DestinationPrefix "0.0.0.0/0" |
          Select-Object -First 1 -ExpandProperty NextHop -ErrorAction SilentlyContinue

    if ($ZAG7hfp8C8x0DOGEryJtsMG -like "$3eIh5OJUVQv.*") { $5EeVpepsyIarv0zq++ }

    $gRcXSETw2 = @("$3eIh5OJUVQv.1","$3eIh5OJUVQv.254","$3eIh5OJUVQv.$(Get-Random -Minimum 5 -Maximum 200)")

    foreach ($EXxhzujgdWA3J in $gRcXSETw2) {
        if (Test-FastPing $EXxhzujgdWA3J) { $5EeVpepsyIarv0zq++; break }
    }

    foreach ($9Wre in @(53,88,389,445)) {
        if (Test-FastPort "$3eIh5OJUVQv.1" $9Wre) { $5EeVpepsyIarv0zq++ }
    }

    if ($5EeVpepsyIarv0zq -ge 2) {
        Write-Host "[+] ACTIVE -> $3eIh5OJUVQv.0/24 (Score:$5EeVpepsyIarv0zq)" -ForegroundColor Cyan
        $IYGUewtP2TlhRVKC += "$3eIh5OJUVQv.0/24"
    }
}

$IYGUewtP2TlhRVKC = $IYGUewtP2TlhRVKC | Sort-Object -Unique





Write-Host ""
Write-Host "========================================="
Write-Host "REACHABLE INTERNAL NETWORKS"
Write-Host "========================================="
Write-Host ""

if ($IYGUewtP2TlhRVKC.Count -eq 0) {
    Write-Host " -> No internal networks confirmed."
}
else {
    foreach ($n4uJtFXOfipTWwjm5 in $IYGUewtP2TlhRVKC) {
        Write-Host " -> $n4uJtFXOfipTWwjm5"
    }
}





Write-Host ""
Write-Host "========================================="
Write-Host "COPY-PASTE FORMAT"
Write-Host "========================================="
Write-Host ""

if ($IYGUewtP2TlhRVKC.Count -gt 0) {

    $jASaNYB12 = ($IYGUewtP2TlhRVKC | ForEach-Object { $_ }) -join ", "

    Write-Host $jASaNYB12
}
else {
    Write-Host "No active networks to export."
}

Write-Host ""
Write-Host "Done."

