#requires -Version 5.1

[CmdletBinding()]
param(
    [string]$DnsServer = "8.8.8.8",
    [string]$InternetHost = "google.com",
    [string[]]$DnsTestDomains = @("google.com", "microsoft.com", "github.com"),
    [string]$RoutingTraceTarget = "1.1.1.1",
    [ValidateRange(1, 15)][int]$TraceMaxHops = 6,
    [string]$TcpTarget = "google.com",
    [int[]]$TcpPorts = @(80, 443, 445, 3389),
    [ValidateRange(300, 5000)][int]$TcpTimeoutMs = 1200,
    [switch]$IncludeWifiScan,
    [ValidateRange(1, 20)][int]$PingCount = 2
)

$ErrorActionPreference = "SilentlyContinue"

Write-Host "=== DIAGNOSTIC RESEAU ===" -ForegroundColor Cyan

# Nom du rapport horodaté
$date = Get-Date -Format "yyyy-MM-dd_HH-mm"
$reportFile = Join-Path -Path $PSScriptRoot -ChildPath "diagnostic_$date.txt"
$jsonReportFile = Join-Path -Path $PSScriptRoot -ChildPath "diagnostic_$date.json"

function New-DiagnosticResult {
    param(
        [string]$DnsServerValue,
        [string]$InternetHostValue,
        [int]$PingCountValue
    )

    [PSCustomObject]@{
        Metadata   = [PSCustomObject]@{
            Timestamp     = (Get-Date).ToString("o")
            ComputerName  = $env:COMPUTERNAME
            UserName      = $env:USERNAME
            PowerShell    = $PSVersionTable.PSVersion.ToString()
            ScriptVersion = "1.1.0"
            DurationMs    = $null
        }
        Parameters = [PSCustomObject]@{
            DnsServer    = $DnsServerValue
            InternetHost = $InternetHostValue
            PingCount    = $PingCountValue
            DnsTestDomains = @()
        }
        Network    = [PSCustomObject]@{
            LocalIPv4       = "Non detectee"
            PrefixLength    = $null
            SubnetMask      = "Non detectee"
            Gateway         = "Non detectee"
            DnsServers      = @()
            DhcpEnabled     = "Inconnu"
            DhcpServer      = "Non detecte"
            DhcpLeaseStart  = $null
            DhcpLeaseEnd    = $null
            IsApipa         = $false
            MacAddress      = "Non detectee"
            LinkSpeed       = "Non detectee"
            InterfaceAlias  = "Non detectee"
            InterfaceStatus = "Non detectee"
        }
        Dns        = [PSCustomObject]@{
            Server       = "Non detecte"
            Domains      = @()
            Entries      = @()
            SuccessCount = 0
            FailureCount = 0
            Status       = "INCONNU"
            Detail       = "Diagnostic DNS non lance"
        }
        Routing    = [PSCustomObject]@{
            TraceTarget       = "Non detecte"
            DefaultRoute      = "Non detectee"
            InterfaceAlias    = "Non detectee"
            NextHopReachable  = $false
            TraceSummary      = @()
            Status            = "INCONNU"
            Detail            = "Diagnostic routage non lance"
        }
        Ports      = [PSCustomObject]@{
            Target       = "Non detecte"
            TimeoutMs    = 0
            Entries      = @()
            OpenCount    = 0
            ClosedCount  = 0
            Status       = "INCONNU"
            Detail       = "Diagnostic ports TCP non lance"
        }
        Wifi       = [PSCustomObject]@{
            Available      = $false
            InterfaceName  = "Non detectee"
            Ssid           = "N/A"
            Bssid          = "N/A"
            RadioType      = "N/A"
            Channel        = "N/A"
            SignalPercent  = $null
            ReceiveRateMbps = $null
            TransmitRateMbps = $null
            Status         = "INCONNU"
            Detail         = "Diagnostic Wi-Fi non lance"
            NearbyCount    = $null
        }
        Tests      = @()
        Summary    = [PSCustomObject]@{
            SuccessCount = 0
            FailureCount = 0
            WarningCount = 0
        }
    }
}

function Convert-PrefixLengthToSubnetMask {
    param(
        [int]$PrefixLength
    )

    if ($PrefixLength -lt 0 -or $PrefixLength -gt 32) {
        return "Non detectee"
    }

    $maskValue = [uint32]::MaxValue
    if ($PrefixLength -eq 0) {
        $maskValue = 0
    }
    else {
        $maskValue = $maskValue -shl (32 - $PrefixLength)
    }

    $bytes = [BitConverter]::GetBytes($maskValue)
    [Array]::Reverse($bytes)
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

function Get-OverallStatus {
    param(
        [PSCustomObject]$Summary
    )

    if ($Summary.FailureCount -gt 0) {
        return "CRITICAL"
    }

    if ($Summary.WarningCount -gt 0) {
        return "WARNING"
    }

    return "HEALTHY"
}

function Get-DhcpDiagnostic {
    param(
        [int]$InterfaceIndex,
        [string]$LocalIPv4,
        [string]$FallbackDhcpEnabled
    )

    $dhcpInfo = [PSCustomObject]@{
        Enabled      = $FallbackDhcpEnabled
        Server       = "Non detecte"
        LeaseStart   = $null
        LeaseEnd     = $null
        IsApipa      = $false
        TestStatus   = "AVERTISSEMENT"
        TestDetail   = "Etat DHCP non determine"
        Source       = "Fallback"
    }

    if ($LocalIPv4 -like "169.254.*") {
        $dhcpInfo.IsApipa = $true
    }

    if ($InterfaceIndex -lt 0) {
        return $dhcpInfo
    }

    try {
        $adapterConfig = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex = $InterfaceIndex"
        if ($adapterConfig) {
            $dhcpInfo.Source = "CIM"
            $dhcpInfo.Enabled = [string]$adapterConfig.DHCPEnabled
            $dhcpInfo.Server = if ($adapterConfig.DHCPServer) { $adapterConfig.DHCPServer } else { "Non detecte" }
            $dhcpInfo.LeaseStart = $adapterConfig.DHCPLeaseObtained
            $dhcpInfo.LeaseEnd = $adapterConfig.DHCPLeaseExpires
        }
    }
    catch {
        $null = $null
    }

    if ($dhcpInfo.IsApipa) {
        $dhcpInfo.TestStatus = "ECHEC"
        $dhcpInfo.TestDetail = "APIPA detectee (169.254.x.x) - attribution DHCP probablement en echec"
        return $dhcpInfo
    }

    if ($dhcpInfo.Enabled -eq "True" -or $dhcpInfo.Enabled -eq "Enabled") {
        if ($dhcpInfo.Server -eq "Non detecte") {
            $dhcpInfo.TestStatus = "AVERTISSEMENT"
            $dhcpInfo.TestDetail = "DHCP actif mais serveur DHCP non detecte"
        }
        else {
            $dhcpInfo.TestStatus = "OK"
            $dhcpInfo.TestDetail = "DHCP actif - serveur $($dhcpInfo.Server)"
        }
    }
    else {
        $dhcpInfo.TestStatus = "AVERTISSEMENT"
        $dhcpInfo.TestDetail = "DHCP desactive (configuration IP statique possible)"
    }

    return $dhcpInfo
}

function Get-DnsResolutionDiagnostic {
    param(
        [string]$DnsServer,
        [string[]]$Domains
    )

    $result = [PSCustomObject]@{
        Server       = $DnsServer
        Domains      = @($Domains)
        Entries      = @()
        SuccessCount = 0
        FailureCount = 0
        Status       = "AVERTISSEMENT"
        Detail       = "Diagnostic DNS partiel"
    }

    if ([string]::IsNullOrWhiteSpace($DnsServer) -or $DnsServer -eq "Non detectee") {
        $result.Status = "ECHEC"
        $result.Detail = "Serveur DNS non disponible pour le test de resolution"
        return $result
    }

    if (-not (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) {
        $result.Status = "AVERTISSEMENT"
        $result.Detail = "Resolve-DnsName indisponible sur ce systeme"
        return $result
    }

    $domainsToTest = @($Domains | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    if ($domainsToTest.Count -eq 0) {
        $result.Status = "AVERTISSEMENT"
        $result.Detail = "Aucun domaine DNS a tester"
        return $result
    }

    foreach ($domain in $domainsToTest) {
        $entryStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $records = Resolve-DnsName -Name $domain -Server $DnsServer -Type A -DnsOnly -ErrorAction Stop
            $entryStopwatch.Stop()

            $ipAddresses = @($records | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress -Unique)
            $status = if ($ipAddresses.Count -gt 0) { "OK" } else { "AVERTISSEMENT" }
            $detail = if ($ipAddresses.Count -gt 0) { "Resolution reussie" } else { "Aucune adresse IPv4 retournee" }

            $result.Entries += [PSCustomObject]@{
                Domain      = $domain
                Status      = $status
                Detail      = $detail
                LatencyMs   = [Math]::Round($entryStopwatch.Elapsed.TotalMilliseconds, 2)
                IpAddresses = $ipAddresses
            }
        }
        catch {
            $entryStopwatch.Stop()
            $result.Entries += [PSCustomObject]@{
                Domain      = $domain
                Status      = "ECHEC"
                Detail      = "Erreur DNS: $($_.Exception.Message)"
                LatencyMs   = [Math]::Round($entryStopwatch.Elapsed.TotalMilliseconds, 2)
                IpAddresses = @()
            }
        }
    }

    $result.SuccessCount = @($result.Entries | Where-Object { $_.Status -eq "OK" }).Count
    $result.FailureCount = @($result.Entries | Where-Object { $_.Status -eq "ECHEC" }).Count

    if ($result.FailureCount -eq $result.Entries.Count) {
        $result.Status = "ECHEC"
        $result.Detail = "Aucune resolution DNS reussie"
    }
    elseif ($result.FailureCount -gt 0) {
        $result.Status = "AVERTISSEMENT"
        $result.Detail = "Resolution DNS partiellement reussie"
    }
    else {
        $result.Status = "OK"
        $result.Detail = "Resolution DNS valide pour tous les domaines testes"
    }

    return $result
}

function Get-RoutingDiagnostic {
    param(
        [string]$Gateway,
        [string]$TraceTarget,
        [int]$MaxHops
    )

    $routing = [PSCustomObject]@{
        TraceTarget      = $TraceTarget
        DefaultRoute     = "Non detectee"
        InterfaceAlias   = "Non detectee"
        NextHopReachable = $false
        TraceSummary     = @()
        Status           = "AVERTISSEMENT"
        Detail           = "Diagnostic routage partiel"
    }

    try {
        $defaultRoute = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" |
            Sort-Object -Property RouteMetric |
            Select-Object -First 1

        if ($defaultRoute) {
            $routing.DefaultRoute = "$($defaultRoute.DestinationPrefix) via $($defaultRoute.NextHop)"
            $routing.InterfaceAlias = $defaultRoute.InterfaceAlias
        }
    }
    catch {
        $routing.DefaultRoute = "Non detectee"
    }

    if (-not [string]::IsNullOrWhiteSpace($Gateway) -and $Gateway -ne "Non detectee") {
        $gatewayPing = Test-Connection -ComputerName $Gateway -Count 1 -Quiet -ErrorAction SilentlyContinue
        $routing.NextHopReachable = [bool]$gatewayPing
    }

    if ([string]::IsNullOrWhiteSpace($TraceTarget)) {
        $routing.Status = "AVERTISSEMENT"
        $routing.Detail = "Aucune cible definie pour le traceroute"
        return $routing
    }

    if (-not (Get-Command tracert.exe -ErrorAction SilentlyContinue)) {
        $routing.Status = "AVERTISSEMENT"
        $routing.Detail = "Commande tracert indisponible"
        return $routing
    }

    try {
        $traceLines = & tracert.exe -d -h $MaxHops -w 600 $TraceTarget 2>$null
        $cleanLines = @($traceLines | Where-Object { $_ -and $_.Trim() -ne "" })
        $routing.TraceSummary = @($cleanLines | Select-Object -First 12)

        $hasCompleted = @($cleanLines | Where-Object { $_ -match "Trace complete" -or $_ -match "Tracage termine" }).Count -gt 0
        if ($hasCompleted -and $routing.NextHopReachable) {
            $routing.Status = "OK"
            $routing.Detail = "Route par defaut presente, passerelle joignable, traceroute termine"
        }
        elseif ($routing.NextHopReachable) {
            $routing.Status = "AVERTISSEMENT"
            $routing.Detail = "Passerelle joignable mais traceroute incomplet ou cible distante filtree"
        }
        else {
            $routing.Status = "ECHEC"
            $routing.Detail = "Passerelle non joignable ou routage degrade"
        }
    }
    catch {
        if ($routing.NextHopReachable) {
            $routing.Status = "AVERTISSEMENT"
            $routing.Detail = "Impossible d'executer le traceroute complet"
        }
        else {
            $routing.Status = "ECHEC"
            $routing.Detail = "Passerelle non joignable et traceroute indisponible"
        }
    }

    return $routing
}

function Get-PortServiceLabel {
    param(
        [int]$Port
    )

    switch ($Port) {
        80 { "HTTP" }
        443 { "HTTPS" }
        445 { "SMB" }
        3389 { "RDP" }
        default { "TCP" }
    }
}

function Test-TcpPortEndpoint {
    param(
        [string]$Target,
        [int]$Port,
        [int]$TimeoutMs
    )

    $client = New-Object System.Net.Sockets.TcpClient
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $async = $client.BeginConnect($Target, $Port, $null, $null)
        $isConnected = $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $isConnected) {
            return [PSCustomObject]@{
                Status    = "CLOSED"
                Detail    = "Timeout"
                LatencyMs = [Math]::Round($timer.Elapsed.TotalMilliseconds, 2)
            }
        }

        $client.EndConnect($async)
        return [PSCustomObject]@{
            Status    = "OPEN"
            Detail    = "Connexion TCP reussie"
            LatencyMs = [Math]::Round($timer.Elapsed.TotalMilliseconds, 2)
        }
    }
    catch {
        return [PSCustomObject]@{
            Status    = "CLOSED"
            Detail    = $_.Exception.Message
            LatencyMs = [Math]::Round($timer.Elapsed.TotalMilliseconds, 2)
        }
    }
    finally {
        $timer.Stop()
        if ($client) { $client.Close() }
    }
}

function Get-TcpPortDiagnostics {
    param(
        [string]$Target,
        [int[]]$Ports,
        [int]$TimeoutMs
    )

    $result = [PSCustomObject]@{
        Target      = $Target
        TimeoutMs   = $TimeoutMs
        Entries     = @()
        OpenCount   = 0
        ClosedCount = 0
        Status      = "AVERTISSEMENT"
        Detail      = "Diagnostic ports partiel"
    }

    if ([string]::IsNullOrWhiteSpace($Target)) {
        $result.Status = "AVERTISSEMENT"
        $result.Detail = "Aucune cible TCP fournie"
        return $result
    }

    $validPorts = @($Ports | Where-Object { $_ -ge 1 -and $_ -le 65535 } | Select-Object -Unique)
    if ($validPorts.Count -eq 0) {
        $result.Status = "AVERTISSEMENT"
        $result.Detail = "Aucun port TCP valide fourni"
        return $result
    }

    foreach ($port in $validPorts) {
        $probe = Test-TcpPortEndpoint -Target $Target -Port $port -TimeoutMs $TimeoutMs
        $result.Entries += [PSCustomObject]@{
            Service   = Get-PortServiceLabel -Port $port
            Port      = $port
            Status    = $probe.Status
            Detail    = $probe.Detail
            LatencyMs = $probe.LatencyMs
        }
    }

    $result.OpenCount = @($result.Entries | Where-Object { $_.Status -eq "OPEN" }).Count
    $result.ClosedCount = @($result.Entries | Where-Object { $_.Status -eq "CLOSED" }).Count

    if ($result.OpenCount -eq 0) {
        $result.Status = "AVERTISSEMENT"
        $result.Detail = "Aucun port TCP teste n'est ouvert sur la cible"
    }
    elseif ($result.ClosedCount -gt 0) {
        $result.Status = "AVERTISSEMENT"
        $result.Detail = "Ports mixtes: certains ouverts, certains fermes"
    }
    else {
        $result.Status = "OK"
        $result.Detail = "Tous les ports TCP testes sont ouverts"
    }

    return $result
}

function Get-WifiDiagnostics {
    param(
        [switch]$IncludeScan
    )

    $wifi = [PSCustomObject]@{
        Available        = $false
        InterfaceName    = "Non detectee"
        Ssid             = "N/A"
        Bssid            = "N/A"
        RadioType        = "N/A"
        Channel          = "N/A"
        SignalPercent    = $null
        ReceiveRateMbps  = $null
        TransmitRateMbps = $null
        Status           = "AVERTISSEMENT"
        Detail           = "Aucune interface Wi-Fi active detectee"
        NearbyCount      = $null
    }

    if (-not (Get-Command netsh.exe -ErrorAction SilentlyContinue)) {
        $wifi.Status = "AVERTISSEMENT"
        $wifi.Detail = "Commande netsh indisponible pour le diagnostic Wi-Fi"
        return $wifi
    }

    $interfaceLines = @(& netsh.exe wlan show interfaces 2>$null)
    if (@($interfaceLines | Where-Object { $_ -match "There is no wireless interface on the system|Aucune interface sans fil" }).Count -gt 0) {
        return $wifi
    }

    foreach ($line in $interfaceLines) {
        if ($line -match "^\s*Name\s*:\s*(.+)$") { $wifi.InterfaceName = $matches[1].Trim(); continue }
        if ($line -match "^\s*SSID\s*:\s*(.+)$" -and $line -notmatch "BSSID") { $wifi.Ssid = $matches[1].Trim(); continue }
        if ($line -match "^\s*BSSID\s*:\s*(.+)$") { $wifi.Bssid = $matches[1].Trim(); continue }
        if ($line -match "^\s*Radio type\s*:\s*(.+)$") { $wifi.RadioType = $matches[1].Trim(); continue }
        if ($line -match "^\s*Channel\s*:\s*(.+)$") { $wifi.Channel = $matches[1].Trim(); continue }
        if ($line -match "^\s*Signal\s*:\s*(\d+)%") { $wifi.SignalPercent = [int]$matches[1]; continue }
        if ($line -match "^\s*Receive rate \(Mbps\)\s*:\s*(\d+)") { $wifi.ReceiveRateMbps = [int]$matches[1]; continue }
        if ($line -match "^\s*Transmit rate \(Mbps\)\s*:\s*(\d+)") { $wifi.TransmitRateMbps = [int]$matches[1]; continue }
    }

    if ($wifi.InterfaceName -ne "Non detectee") {
        $wifi.Available = $true
    }

    if ($IncludeScan -and $wifi.Available) {
        $networkLines = @(& netsh.exe wlan show networks mode=bssid 2>$null)
        $ssidCount = @($networkLines | Where-Object { $_ -match "^\s*SSID\s+\d+\s*:" }).Count
        $wifi.NearbyCount = $ssidCount
    }

    if (-not $wifi.Available) {
        $wifi.Status = "AVERTISSEMENT"
        $wifi.Detail = "Aucune interface Wi-Fi detectee"
    }
    elseif ($wifi.Ssid -eq "" -or $wifi.Ssid -eq "N/A") {
        $wifi.Status = "AVERTISSEMENT"
        $wifi.Detail = "Interface Wi-Fi presente mais non connectee"
    }
    elseif ($wifi.SignalPercent -lt 40) {
        $wifi.Status = "AVERTISSEMENT"
        $wifi.Detail = "Wi-Fi connecte mais signal faible"
    }
    else {
        $wifi.Status = "OK"
        $wifi.Detail = "Wi-Fi connecte et signal correct"
    }

    return $wifi
}

# Récupération de l'interface active (IPv4)
$activeConfig = $null
try {
    $activeConfig = Get-NetIPConfiguration |
        Where-Object { $_.IPv4Address -and $_.NetAdapter.Status -eq "Up" } |
        Select-Object -First 1
}
catch {
    $activeConfig = $null
}

$localIp = if ($activeConfig) { $activeConfig.IPv4Address.IPAddress } else { "Non detectee" }
$prefixLength = if ($activeConfig -and $activeConfig.IPv4Address) { $activeConfig.IPv4Address.PrefixLength } else { $null }
$subnetMask = if ($prefixLength -ne $null) { Convert-PrefixLengthToSubnetMask -PrefixLength $prefixLength } else { "Non detectee" }
$gateway = if ($activeConfig -and $activeConfig.IPv4DefaultGateway) { $activeConfig.IPv4DefaultGateway.NextHop } else { "Non detectee" }
$dnsServers = if ($activeConfig -and $activeConfig.DNSServer -and $activeConfig.DNSServer.ServerAddresses) { @($activeConfig.DNSServer.ServerAddresses) } else { @() }
$dhcpEnabled = if ($activeConfig -and $activeConfig.NetIPv4Interface) { [string]$activeConfig.NetIPv4Interface.Dhcp } else { "Inconnu" }
$interfaceIndex = if ($activeConfig) { [int]$activeConfig.InterfaceIndex } else { -1 }
$macAddress = if ($activeConfig -and $activeConfig.NetAdapter) { $activeConfig.NetAdapter.MacAddress } else { "Non detectee" }
$linkSpeed = if ($activeConfig -and $activeConfig.NetAdapter) { [string]$activeConfig.NetAdapter.LinkSpeed } else { "Non detectee" }
$interfaceAlias = if ($activeConfig) { $activeConfig.InterfaceAlias } else { "Non detectee" }
$interfaceStatus = if ($activeConfig -and $activeConfig.NetAdapter) { $activeConfig.NetAdapter.Status } else { "Non detectee" }
$dhcpDiagnostic = Get-DhcpDiagnostic -InterfaceIndex $interfaceIndex -LocalIPv4 $localIp -FallbackDhcpEnabled $dhcpEnabled
$effectiveDnsServer = if ([string]::IsNullOrWhiteSpace($DnsServer)) {
    if ($dnsServers.Count -gt 0) { $dnsServers[0] } else { "Non detectee" }
}
else {
    $DnsServer
}
$dnsResolutionDiagnostic = Get-DnsResolutionDiagnostic -DnsServer $effectiveDnsServer -Domains $DnsTestDomains
$routingDiagnostic = Get-RoutingDiagnostic -Gateway $gateway -TraceTarget $RoutingTraceTarget -MaxHops $TraceMaxHops
$effectiveTcpTarget = if ([string]::IsNullOrWhiteSpace($TcpTarget)) { $InternetHost } else { $TcpTarget }
$tcpPortDiagnostic = Get-TcpPortDiagnostics -Target $effectiveTcpTarget -Ports $TcpPorts -TimeoutMs $TcpTimeoutMs
$wifiDiagnostic = Get-WifiDiagnostics -IncludeScan:$IncludeWifiScan

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$diagnosticResult = New-DiagnosticResult -DnsServerValue $DnsServer -InternetHostValue $InternetHost -PingCountValue $PingCount
$diagnosticResult.Parameters.DnsTestDomains = @($DnsTestDomains)
$diagnosticResult.Parameters.RoutingTraceTarget = $RoutingTraceTarget
$diagnosticResult.Parameters.TraceMaxHops = $TraceMaxHops
$diagnosticResult.Parameters.TcpTarget = $effectiveTcpTarget
$diagnosticResult.Parameters.TcpPorts = @($TcpPorts)
$diagnosticResult.Parameters.TcpTimeoutMs = $TcpTimeoutMs
$diagnosticResult.Parameters.IncludeWifiScan = [bool]$IncludeWifiScan
$diagnosticResult.Network.LocalIPv4 = $localIp
$diagnosticResult.Network.PrefixLength = $prefixLength
$diagnosticResult.Network.SubnetMask = $subnetMask
$diagnosticResult.Network.Gateway = $gateway
$diagnosticResult.Network.DnsServers = $dnsServers
$diagnosticResult.Network.DhcpEnabled = $dhcpDiagnostic.Enabled
$diagnosticResult.Network.DhcpServer = $dhcpDiagnostic.Server
$diagnosticResult.Network.DhcpLeaseStart = $dhcpDiagnostic.LeaseStart
$diagnosticResult.Network.DhcpLeaseEnd = $dhcpDiagnostic.LeaseEnd
$diagnosticResult.Network.IsApipa = $dhcpDiagnostic.IsApipa
$diagnosticResult.Network.MacAddress = $macAddress
$diagnosticResult.Network.LinkSpeed = $linkSpeed
$diagnosticResult.Network.InterfaceAlias = $interfaceAlias
$diagnosticResult.Network.InterfaceStatus = $interfaceStatus
$diagnosticResult.Dns = $dnsResolutionDiagnostic
$diagnosticResult.Routing = $routingDiagnostic
$diagnosticResult.Ports = $tcpPortDiagnostic
$diagnosticResult.Wifi = $wifiDiagnostic

# Fonction utilitaire de test ping
function Test-NetworkTarget {
    param(
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ([string]::IsNullOrWhiteSpace($Target) -or $Target -eq "Non detectee") {
        return [PSCustomObject]@{
            Test              = $Label
            Cible             = $Target
            Statut            = "ECHEC"
            Detail            = "Cible indisponible"
            AttemptCount      = $PingCount
            SuccessCount      = 0
            PacketLossPercent = 100
            AverageLatencyMs  = $null
            MaxLatencyMs      = $null
        }
    }

    $pingResults = Test-Connection -ComputerName $Target -Count $PingCount -ErrorAction SilentlyContinue
    $successCount = @($pingResults).Count
    $result = $successCount -gt 0
    $latencies = @($pingResults | ForEach-Object { $_.ResponseTime } | Where-Object { $_ -ne $null })
    $packetLossPercent = if ($PingCount -gt 0) {
        [Math]::Round((($PingCount - $successCount) / [double]$PingCount) * 100, 2)
    }
    else {
        0
    }

    [PSCustomObject]@{
        Test              = $Label
        Cible             = $Target
        Statut            = if ($result) { "OK" } else { "ECHEC" }
        Detail            = if ($result) { "Connexion reussie" } else { "Aucune reponse" }
        AttemptCount      = $PingCount
        SuccessCount      = $successCount
        PacketLossPercent = $packetLossPercent
        AverageLatencyMs  = if ($latencies.Count -gt 0) { [Math]::Round(($latencies | Measure-Object -Average).Average, 2) } else { $null }
        MaxLatencyMs      = if ($latencies.Count -gt 0) { ($latencies | Measure-Object -Maximum).Maximum } else { $null }
    }
}

Write-Host "`n[1] Adresse IP locale :" -ForegroundColor Yellow
Write-Host "IP : $localIp"
Write-Host "Masque : $subnetMask"
Write-Host "Passerelle : $gateway"
Write-Host "Interface : $interfaceAlias ($interfaceStatus)"
Write-Host "Vitesse lien : $linkSpeed"
Write-Host "DHCP : $($dhcpDiagnostic.Enabled)"
Write-Host "Serveur DHCP : $($dhcpDiagnostic.Server)"
Write-Host "DNS detectes : $(if ($dnsServers.Count -gt 0) { $dnsServers -join ', ' } else { 'Non detectes' })"

Write-Host "`n[2] Test connexion Internet ($InternetHost) :" -ForegroundColor Yellow
$internetTest = Test-NetworkTarget -Target $InternetHost -Label "Connexion Internet"
Write-Host "$($internetTest.Statut) - $($internetTest.Detail)"
$diagnosticResult.Tests += $internetTest

Write-Host "`n[3] Test passerelle ($gateway) :" -ForegroundColor Yellow
$gatewayTest = Test-NetworkTarget -Target $gateway -Label "Passerelle"
Write-Host "$($gatewayTest.Statut) - $($gatewayTest.Detail)"
$diagnosticResult.Tests += $gatewayTest

Write-Host "`n[4] Test DNS ($effectiveDnsServer) :" -ForegroundColor Yellow
$dnsTest = Test-NetworkTarget -Target $effectiveDnsServer -Label "DNS"
Write-Host "$($dnsTest.Statut) - $($dnsTest.Detail)"
$diagnosticResult.Tests += $dnsTest

Write-Host "`n[5] Test DHCP :" -ForegroundColor Yellow
$dhcpTest = [PSCustomObject]@{
    Test              = "DHCP"
    Cible             = $dhcpDiagnostic.Server
    Statut            = $dhcpDiagnostic.TestStatus
    Detail            = $dhcpDiagnostic.TestDetail
    AttemptCount      = 0
    SuccessCount      = 0
    PacketLossPercent = $null
    AverageLatencyMs  = $null
    MaxLatencyMs      = $null
}
Write-Host "$($dhcpTest.Statut) - $($dhcpTest.Detail)"
$diagnosticResult.Tests += $dhcpTest

Write-Host "`n[6] Test resolution DNS :" -ForegroundColor Yellow
$dnsResolutionTest = [PSCustomObject]@{
    Test              = "DNS Resolution"
    Cible             = $effectiveDnsServer
    Statut            = $dnsResolutionDiagnostic.Status
    Detail            = $dnsResolutionDiagnostic.Detail
    AttemptCount      = @($dnsResolutionDiagnostic.Entries).Count
    SuccessCount      = $dnsResolutionDiagnostic.SuccessCount
    PacketLossPercent = $null
    AverageLatencyMs  = $null
    MaxLatencyMs      = $null
}
Write-Host "$($dnsResolutionTest.Statut) - $($dnsResolutionTest.Detail)"
$diagnosticResult.Tests += $dnsResolutionTest

Write-Host "`n[7] Test routage :" -ForegroundColor Yellow
$routingTest = [PSCustomObject]@{
    Test              = "Routing"
    Cible             = $RoutingTraceTarget
    Statut            = $routingDiagnostic.Status
    Detail            = $routingDiagnostic.Detail
    AttemptCount      = 1
    SuccessCount      = if ($routingDiagnostic.Status -eq "OK") { 1 } else { 0 }
    PacketLossPercent = $null
    AverageLatencyMs  = $null
    MaxLatencyMs      = $null
}
Write-Host "$($routingTest.Statut) - $($routingTest.Detail)"
Write-Host "Route defaut : $($routingDiagnostic.DefaultRoute)"
Write-Host "Interface route : $($routingDiagnostic.InterfaceAlias)"
Write-Host "Passerelle joignable : $(if ($routingDiagnostic.NextHopReachable) { 'Oui' } else { 'Non' })"
$diagnosticResult.Tests += $routingTest

Write-Host "`n[8] Test ports TCP ($effectiveTcpTarget) :" -ForegroundColor Yellow
foreach ($entry in $tcpPortDiagnostic.Entries) {
    Write-Host "$($entry.Service) $($entry.Port) : $($entry.Status) ($($entry.LatencyMs) ms)"
}
$tcpPortTest = [PSCustomObject]@{
    Test              = "TCP Ports"
    Cible             = $effectiveTcpTarget
    Statut            = $tcpPortDiagnostic.Status
    Detail            = $tcpPortDiagnostic.Detail
    AttemptCount      = @($tcpPortDiagnostic.Entries).Count
    SuccessCount      = $tcpPortDiagnostic.OpenCount
    PacketLossPercent = $null
    AverageLatencyMs  = if (@($tcpPortDiagnostic.Entries).Count -gt 0) { [Math]::Round((@($tcpPortDiagnostic.Entries | Measure-Object -Property LatencyMs -Average).Average), 2) } else { $null }
    MaxLatencyMs      = if (@($tcpPortDiagnostic.Entries).Count -gt 0) { (@($tcpPortDiagnostic.Entries | Measure-Object -Property LatencyMs -Maximum).Maximum) } else { $null }
}
Write-Host "$($tcpPortTest.Statut) - $($tcpPortTest.Detail)"
$diagnosticResult.Tests += $tcpPortTest

Write-Host "`n[9] Test Wi-Fi :" -ForegroundColor Yellow
$wifiTest = [PSCustomObject]@{
    Test              = "Wi-Fi"
    Cible             = $wifiDiagnostic.InterfaceName
    Statut            = $wifiDiagnostic.Status
    Detail            = $wifiDiagnostic.Detail
    AttemptCount      = 1
    SuccessCount      = if ($wifiDiagnostic.Status -eq "OK") { 1 } else { 0 }
    PacketLossPercent = $null
    AverageLatencyMs  = $null
    MaxLatencyMs      = $null
}
Write-Host "$($wifiTest.Statut) - $($wifiTest.Detail)"
Write-Host "Interface Wi-Fi : $($wifiDiagnostic.InterfaceName)"
Write-Host "SSID : $($wifiDiagnostic.Ssid)"
Write-Host "Signal : $(if ($wifiDiagnostic.SignalPercent -ne $null) { "$($wifiDiagnostic.SignalPercent)%" } else { 'N/A' })"
Write-Host "Canal : $($wifiDiagnostic.Channel)"
$diagnosticResult.Tests += $wifiTest

$diagnosticResult.Summary.SuccessCount = @($diagnosticResult.Tests | Where-Object { $_.Statut -eq "OK" }).Count
$diagnosticResult.Summary.FailureCount = @($diagnosticResult.Tests | Where-Object { $_.Statut -eq "ECHEC" }).Count
$diagnosticResult.Summary.WarningCount = @($diagnosticResult.Tests | Where-Object { $_.Statut -eq "AVERTISSEMENT" }).Count
$overallStatus = Get-OverallStatus -Summary $diagnosticResult.Summary

# Construction du rapport
$reportLines = @(
    "=== DIAGNOSTIC RESEAU ===",
    "Date : $(Get-Date -Format \"dd/MM/yyyy HH:mm:ss\")",
    "Machine : $env:COMPUTERNAME",
    "Utilisateur : $env:USERNAME",
    "",
    "[1] Configuration locale",
    "Interface : $interfaceAlias ($interfaceStatus)",
    "IP locale : $localIp",
    "Masque : $subnetMask",
    "MAC : $macAddress",
    "Vitesse lien : $linkSpeed",
    "Passerelle : $gateway",
    "DHCP : $($dhcpDiagnostic.Enabled)",
    "Serveur DHCP : $($dhcpDiagnostic.Server)",
    "Bail DHCP debut : $(if ($dhcpDiagnostic.LeaseStart) { $dhcpDiagnostic.LeaseStart } else { 'Non detecte' })",
    "Bail DHCP fin : $(if ($dhcpDiagnostic.LeaseEnd) { $dhcpDiagnostic.LeaseEnd } else { 'Non detecte' })",
    "APIPA : $(if ($dhcpDiagnostic.IsApipa) { 'Oui' } else { 'Non' })",
    "DNS detectes : $(if ($dnsServers.Count -gt 0) { $dnsServers -join ', ' } else { 'Non detectes' })",
    "",
    "[2] Resultats des tests",
    "- $($internetTest.Test) [$($internetTest.Cible)] : $($internetTest.Statut) - $($internetTest.Detail)",
    "- $($gatewayTest.Test) [$($gatewayTest.Cible)] : $($gatewayTest.Statut) - $($gatewayTest.Detail)",
    "- $($dnsTest.Test) [$($dnsTest.Cible)] : $($dnsTest.Statut) - $($dnsTest.Detail)",
    "- $($dhcpTest.Test) [$($dhcpTest.Cible)] : $($dhcpTest.Statut) - $($dhcpTest.Detail)",
    "- $($dnsResolutionTest.Test) [$($dnsResolutionTest.Cible)] : $($dnsResolutionTest.Statut) - $($dnsResolutionTest.Detail)",
    "- $($routingTest.Test) [$($routingTest.Cible)] : $($routingTest.Statut) - $($routingTest.Detail)",
    "- $($tcpPortTest.Test) [$($tcpPortTest.Cible)] : $($tcpPortTest.Statut) - $($tcpPortTest.Detail)",
    "- $($wifiTest.Test) [$($wifiTest.Cible)] : $($wifiTest.Statut) - $($wifiTest.Detail)",
    "",
    "[3] DNS resolution details",
    "Serveur teste : $effectiveDnsServer",
    "Domaines testes : $(@($dnsResolutionDiagnostic.Domains) -join ', ')",
    "Succes : $($dnsResolutionDiagnostic.SuccessCount)",
    "Echecs : $($dnsResolutionDiagnostic.FailureCount)",
    "Statut : $($dnsResolutionDiagnostic.Status) - $($dnsResolutionDiagnostic.Detail)",
    "",
    "[4] Routing details",
    "Cible traceroute : $RoutingTraceTarget",
    "Route defaut : $($routingDiagnostic.DefaultRoute)",
    "Interface : $($routingDiagnostic.InterfaceAlias)",
    "Passerelle joignable : $(if ($routingDiagnostic.NextHopReachable) { 'Oui' } else { 'Non' })",
    "Statut : $($routingDiagnostic.Status) - $($routingDiagnostic.Detail)",
    "",
    "[5] TCP ports details",
    "Cible : $effectiveTcpTarget",
    "Ports testes : $(@($TcpPorts) -join ', ')",
    "Ouverts : $($tcpPortDiagnostic.OpenCount)",
    "Fermes : $($tcpPortDiagnostic.ClosedCount)",
    "Statut : $($tcpPortDiagnostic.Status) - $($tcpPortDiagnostic.Detail)",
    "",
    "[6] Wi-Fi details",
    "Interface : $($wifiDiagnostic.InterfaceName)",
    "SSID : $($wifiDiagnostic.Ssid)",
    "BSSID : $($wifiDiagnostic.Bssid)",
    "Signal : $(if ($wifiDiagnostic.SignalPercent -ne $null) { "$($wifiDiagnostic.SignalPercent)%" } else { 'N/A' })",
    "Canal : $($wifiDiagnostic.Channel)",
    "Radio : $($wifiDiagnostic.RadioType)",
    "Debit RX/TX (Mbps) : $(if ($wifiDiagnostic.ReceiveRateMbps -ne $null -and $wifiDiagnostic.TransmitRateMbps -ne $null) { "$($wifiDiagnostic.ReceiveRateMbps)/$($wifiDiagnostic.TransmitRateMbps)" } else { 'N/A' })",
    "Reseaux detectes : $(if ($wifiDiagnostic.NearbyCount -ne $null) { $wifiDiagnostic.NearbyCount } else { 'N/A' })",
    "Statut : $($wifiDiagnostic.Status) - $($wifiDiagnostic.Detail)",
    "",
    "[7] Resume",
    "Etat global : $overallStatus",
    "Succes : $($diagnosticResult.Summary.SuccessCount)",
    "Echecs : $($diagnosticResult.Summary.FailureCount)",
    "Avertissements : $($diagnosticResult.Summary.WarningCount)",
    "",
    "[8] ipconfig /all",
    ""
)

foreach ($entry in $dnsResolutionDiagnostic.Entries) {
    $ipValue = if (@($entry.IpAddresses).Count -gt 0) { @($entry.IpAddresses) -join ", " } else { "N/A" }
    $reportLines += "- $($entry.Domain) : $($entry.Status) - $($entry.Detail) - Latence $($entry.LatencyMs) ms - IP $ipValue"
}

if (@($routingDiagnostic.TraceSummary).Count -gt 0) {
    $reportLines += ""
    $reportLines += "[Traceroute extrait]"
    $reportLines += @($routingDiagnostic.TraceSummary)
}

if (@($tcpPortDiagnostic.Entries).Count -gt 0) {
    $reportLines += ""
    $reportLines += "[TCP ports extrait]"
    foreach ($entry in $tcpPortDiagnostic.Entries) {
        $reportLines += "- $($entry.Service) $($entry.Port): $($entry.Status) - $($entry.Detail) - $($entry.LatencyMs) ms"
    }
}

$stopwatch.Stop()
$diagnosticResult.Metadata.DurationMs = $stopwatch.ElapsedMilliseconds
$diagnosticResult | Add-Member -MemberType NoteProperty -Name OverallStatus -Value $overallStatus -Force

$reportLines | Out-File -FilePath $reportFile -Encoding UTF8
ipconfig /all | Out-File -FilePath $reportFile -Append -Encoding UTF8
$diagnosticResult | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonReportFile -Encoding UTF8

Write-Host "`n[10] Sauvegarde du rapport..." -ForegroundColor Yellow
Write-Host "Diagnostic termine. Rapport TXT sauvegarde : $reportFile" -ForegroundColor Green
Write-Host "Rapport JSON sauvegarde : $jsonReportFile" -ForegroundColor Green
