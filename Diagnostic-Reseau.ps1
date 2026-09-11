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
    [string]$LoadTestTarget = "cloudflare.com",
    [string]$LoadTestMonitorTarget = "8.8.8.8",
    [ValidateRange(3, 30)][int]$LoadTestSampleCount = 6,
    [ValidateRange(2, 20)][int]$LoadTestDurationSec = 6,
    [ValidateRange(1, 6)][int]$LoadTestParallelStreams = 2,
    [switch]$EnableBandwidthTest,
    [string]$BandwidthTestUrl = "https://proof.ovh.net/files/10Mb.dat",
    [ValidateRange(1, 60)][int]$BandwidthTimeoutSec = 20,
    [switch]$GenerateDashboard = $true,
    [switch]$OpenDashboard,
    [ValidateRange(1, 20)][int]$PingCount = 2
)

$ErrorActionPreference = "SilentlyContinue"

Write-Host "=== DIAGNOSTIC RESEAU ===" -ForegroundColor Cyan

# Nom du rapport horodaté
$date = Get-Date -Format "yyyy-MM-dd_HH-mm"
$reportFile = Join-Path -Path $PSScriptRoot -ChildPath "diagnostic_$date.txt"
$jsonReportFile = Join-Path -Path $PSScriptRoot -ChildPath "diagnostic_$date.json"
$htmlReportFile = Join-Path -Path $PSScriptRoot -ChildPath "diagnostic_$date.html"

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
        LoadTest   = [PSCustomObject]@{
            Target             = "Non detecte"
            MonitorTarget      = "Non detecte"
            DurationSec        = 0
            ParallelStreams    = 0
            Before             = $null
            UnderLoad          = $null
            After              = $null
            AvgLatencyDeltaMs  = $null
            MaxLatencyDeltaMs  = $null
            Status             = "INCONNU"
            Detail             = "Test de charge non lance"
        }
        Bandwidth  = [PSCustomObject]@{
            Enabled          = $false
            TestUrl          = "N/A"
            DownloadMbps     = $null
            DownloadBytes    = $null
            DurationMs       = $null
            Status           = "INCONNU"
            Detail           = "Test de debit non lance"
        }
        Analysis   = [PSCustomObject]@{
            Findings         = @()
            Recommendations  = @()
            Status           = "INCONNU"
            Detail           = "Analyse non lancee"
        }
        Score      = [PSCustomObject]@{
            Value            = $null
            Max              = 100
            Method           = "v1"
            Level            = "INCONNU"
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

function Measure-PingMetrics {
    param(
        [string]$Target,
        [int]$Count
    )

    $result = [PSCustomObject]@{
        Target            = $Target
        AttemptCount      = $Count
        SuccessCount      = 0
        PacketLossPercent = 100
        AverageLatencyMs  = $null
        MaxLatencyMs      = $null
    }

    if ([string]::IsNullOrWhiteSpace($Target) -or $Count -lt 1) {
        return $result
    }

    $pingResults = Test-Connection -ComputerName $Target -Count $Count -ErrorAction SilentlyContinue
    $successCount = @($pingResults).Count
    $latencies = @($pingResults | ForEach-Object { $_.ResponseTime } | Where-Object { $_ -ne $null })

    $result.SuccessCount = $successCount
    $result.PacketLossPercent = [Math]::Round((($Count - $successCount) / [double]$Count) * 100, 2)
    if ($latencies.Count -gt 0) {
        $result.AverageLatencyMs = [Math]::Round(($latencies | Measure-Object -Average).Average, 2)
        $result.MaxLatencyMs = ($latencies | Measure-Object -Maximum).Maximum
    }

    return $result
}

function Invoke-ControlledNetworkLoadTest {
    param(
        [string]$LoadTarget,
        [string]$MonitorTarget,
        [int]$SampleCount,
        [int]$DurationSec,
        [int]$ParallelStreams
    )

    $loadResult = [PSCustomObject]@{
        Target            = $LoadTarget
        MonitorTarget     = $MonitorTarget
        DurationSec       = $DurationSec
        ParallelStreams   = $ParallelStreams
        Before            = $null
        UnderLoad         = $null
        After             = $null
        AvgLatencyDeltaMs = $null
        MaxLatencyDeltaMs = $null
        Status            = "AVERTISSEMENT"
        Detail            = "Test de charge partiel"
    }

    if ([string]::IsNullOrWhiteSpace($LoadTarget) -or [string]::IsNullOrWhiteSpace($MonitorTarget)) {
        $loadResult.Status = "AVERTISSEMENT"
        $loadResult.Detail = "Cible de charge ou cible de mesure manquante"
        return $loadResult
    }

    $loadPingCountPerStream = [Math]::Max(2, [Math]::Ceiling(($DurationSec * 2) / [Math]::Max(1, $ParallelStreams)))

    $loadResult.Before = Measure-PingMetrics -Target $MonitorTarget -Count $SampleCount

    $jobs = @()
    for ($i = 1; $i -le $ParallelStreams; $i++) {
        $jobs += Start-Job -ScriptBlock {
            param($target, $count)
            Test-Connection -ComputerName $target -Count $count -ErrorAction SilentlyContinue | Out-Null
        } -ArgumentList $LoadTarget, $loadPingCountPerStream
    }

    $loadResult.UnderLoad = Measure-PingMetrics -Target $MonitorTarget -Count $SampleCount

    foreach ($job in $jobs) {
        Wait-Job -Job $job -Timeout ($DurationSec + 3) | Out-Null
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue | Out-Null
    }

    $loadResult.After = Measure-PingMetrics -Target $MonitorTarget -Count $SampleCount

    $beforeAvg = $loadResult.Before.AverageLatencyMs
    $underAvg = $loadResult.UnderLoad.AverageLatencyMs
    $beforeMax = $loadResult.Before.MaxLatencyMs
    $underMax = $loadResult.UnderLoad.MaxLatencyMs

    if ($beforeAvg -ne $null -and $underAvg -ne $null) {
        $loadResult.AvgLatencyDeltaMs = [Math]::Round(($underAvg - $beforeAvg), 2)
    }
    if ($beforeMax -ne $null -and $underMax -ne $null) {
        $loadResult.MaxLatencyDeltaMs = [Math]::Round(($underMax - $beforeMax), 2)
    }

    $underLoss = $loadResult.UnderLoad.PacketLossPercent
    if ($underLoss -ge 10) {
        $loadResult.Status = "ECHEC"
        $loadResult.Detail = "Perte de paquets elevee detectee sous charge"
    }
    elseif ($loadResult.AvgLatencyDeltaMs -ge 20 -or $underLoss -gt 0) {
        $loadResult.Status = "AVERTISSEMENT"
        $loadResult.Detail = "Degradation de latence detectee sous charge"
    }
    else {
        $loadResult.Status = "OK"
        $loadResult.Detail = "Comportement reseau stable sous charge controlee"
    }

    return $loadResult
}

function Invoke-BandwidthDiagnostic {
    param(
        [switch]$Enabled,
        [string]$TestUrl,
        [int]$TimeoutSec
    )

    $bandwidth = [PSCustomObject]@{
        Enabled       = [bool]$Enabled
        TestUrl       = $TestUrl
        DownloadMbps  = $null
        DownloadBytes = $null
        DurationMs    = $null
        Status        = "INFO"
        Detail        = "Test de debit desactive"
    }

    if (-not $Enabled) {
        return $bandwidth
    }

    if ([string]::IsNullOrWhiteSpace($TestUrl)) {
        $bandwidth.Status = "AVERTISSEMENT"
        $bandwidth.Detail = "URL de test debit manquante"
        return $bandwidth
    }

    try {
        $request = [System.Net.HttpWebRequest]::Create($TestUrl)
        $request.Method = "GET"
        $request.Timeout = $TimeoutSec * 1000
        $request.ReadWriteTimeout = $TimeoutSec * 1000
        $request.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
        if ($request.Proxy) {
            $request.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
        }
        $request.Headers["Cache-Control"] = "no-cache"
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $response = $request.GetResponse()
        $stream = $response.GetResponseStream()
        $buffer = New-Object byte[] 32768
        $bytes = 0
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $bytes += $read
        }
        $stream.Close()
        $response.Close()
        $timer.Stop()

        $seconds = [Math]::Max(0.001, $timer.Elapsed.TotalSeconds)
        $mbps = [Math]::Round((($bytes * 8) / 1MB) / $seconds, 2)

        $bandwidth.DownloadBytes = $bytes
        $bandwidth.DurationMs = [Math]::Round($timer.Elapsed.TotalMilliseconds, 2)
        $bandwidth.DownloadMbps = $mbps
        $bandwidth.Status = "OK"
        $bandwidth.Detail = "Debit descendant mesure avec succes"
    }
    catch {
        $bandwidth.Status = "AVERTISSEMENT"
        $bandwidth.Detail = "Mesure de debit indisponible: $($_.Exception.Message)"
    }

    return $bandwidth
}

function Get-DiagnosticAnalysis {
    param(
        [PSCustomObject]$ResultObject
    )

    $analysis = [PSCustomObject]@{
        Findings        = @()
        Recommendations = @()
        Status          = "HEALTHY"
        Detail          = "Aucun incident critique detecte"
    }

    foreach ($test in $ResultObject.Tests) {
        if ($test.Statut -eq "ECHEC") {
            $analysis.Findings += "ECHEC - $($test.Test): $($test.Detail)"
        }
        elseif ($test.Statut -eq "AVERTISSEMENT") {
            $analysis.Findings += "AVERTISSEMENT - $($test.Test): $($test.Detail)"
        }
    }

    if ($ResultObject.Network.IsApipa) {
        $analysis.Recommendations += "Renouveler le bail DHCP (ipconfig /release puis /renew) et verifier le serveur DHCP."
    }

    if ($ResultObject.Routing.NextHopReachable -eq $false) {
        $analysis.Recommendations += "Verifier la passerelle par defaut, le cablage et le VLAN du poste."
    }

    if ($ResultObject.Dns.FailureCount -gt 0) {
        $analysis.Recommendations += "Verifier la disponibilite des serveurs DNS et la resolution des domaines internes."
    }

    if ($ResultObject.Ports.ClosedCount -gt 0) {
        $analysis.Recommendations += "Verifier les pare-feux et l'accessibilite des services TCP attendus."
    }

    if ($ResultObject.Wifi.Status -eq "AVERTISSEMENT" -and $ResultObject.Wifi.SignalPercent -ne $null -and $ResultObject.Wifi.SignalPercent -lt 40) {
        $analysis.Recommendations += "Ameliorer la qualite du signal Wi-Fi (position, canal, borne)."
    }

    if ($ResultObject.LoadTest.Status -eq "AVERTISSEMENT" -or $ResultObject.LoadTest.Status -eq "ECHEC") {
        $analysis.Recommendations += "Investiguer la congestion reseau: latence degradee detectee sous charge controlee."
    }

    if ($analysis.Recommendations.Count -eq 0) {
        $analysis.Recommendations += "Aucune action immediate requise."
    }

    $hasError = @($ResultObject.Tests | Where-Object { $_.Statut -eq "ECHEC" }).Count -gt 0
    $hasWarning = @($ResultObject.Tests | Where-Object { $_.Statut -eq "AVERTISSEMENT" }).Count -gt 0
    if ($hasError) {
        $analysis.Status = "CRITICAL"
        $analysis.Detail = "Au moins un test critique est en echec"
    }
    elseif ($hasWarning) {
        $analysis.Status = "WARNING"
        $analysis.Detail = "Des avertissements necessitent verification"
    }

    return $analysis
}

function Get-DiagnosticScore {
    param(
        [PSCustomObject]$ResultObject
    )

    $score = 100
    $score -= (@($ResultObject.Tests | Where-Object { $_.Statut -eq "ECHEC" }).Count * 20)
    $score -= (@($ResultObject.Tests | Where-Object { $_.Statut -eq "AVERTISSEMENT" }).Count * 8)

    if ($ResultObject.LoadTest.Status -eq "ECHEC") { $score -= 10 }
    elseif ($ResultObject.LoadTest.Status -eq "AVERTISSEMENT") { $score -= 5 }

    if ($score -lt 0) { $score = 0 }
    if ($score -gt 100) { $score = 100 }

    $errorCount = @($ResultObject.Tests | Where-Object { $_.Statut -eq "ECHEC" }).Count
    $warningCount = @($ResultObject.Tests | Where-Object { $_.Statut -eq "AVERTISSEMENT" }).Count

    $level = "HEALTHY"
    if ($errorCount -gt 0 -or $score -lt 50) { $level = "CRITICAL" }
    elseif ($warningCount -gt 0 -or $score -lt 80) { $level = "WARNING" }

    return [PSCustomObject]@{
        Value  = $score
        Max    = 100
        Method = "v1"
        Level  = $level
    }
}

function New-DiagnosticDashboardHtml {
    param(
        [PSCustomObject]$ResultObject,
        [string]$OutputPath
    )

    $jsonData = ($ResultObject | ConvertTo-Json -Depth 8)
    $jsonData = $jsonData -replace "</script>", "<\/script>"

    $html = @"
<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Diagnostic Reseau - $($ResultObject.Metadata.ComputerName)</title>
  <style>
    :root{--bg:#0b1220;--panel:#111a2b;--muted:#8da0be;--txt:#e6edf7;--ok:#26b364;--warn:#e3b341;--err:#f85149;--acc:#4cb3ff;}
    *{box-sizing:border-box} body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:radial-gradient(circle at 10% 10%,#1c2b47 0,#0b1220 45%,#070d18 100%);color:var(--txt)}
    .wrap{max-width:1200px;margin:24px auto;padding:0 16px}
    .head{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;margin-bottom:16px}
    .title{font-size:28px;font-weight:700;letter-spacing:.3px}
    .sub{color:var(--muted);font-size:13px}
    .grid{display:grid;grid-template-columns:repeat(5,minmax(120px,1fr));gap:12px}
    .card,.panel{background:linear-gradient(180deg,#121d30,#0f1829);border:1px solid #22314d;border-radius:12px;padding:14px}
    .k{font-size:12px;color:var(--muted)} .v{font-size:24px;font-weight:700;margin-top:4px}
    .ok{color:var(--ok)} .warn{color:var(--warn)} .err{color:var(--err)} .acc{color:var(--acc)}
    .layout{display:grid;grid-template-columns:1.1fr 1fr;gap:12px;margin-top:12px}
    .panel h3{margin:0 0 10px;font-size:15px}
    table{width:100%;border-collapse:collapse;font-size:13px}
    th,td{padding:6px 4px;border-bottom:1px solid #21314f;text-align:left}
    .badge{padding:3px 8px;border-radius:999px;font-size:12px;font-weight:600}
    .b-ok{background:rgba(38,179,100,.18);color:var(--ok)} .b-warn{background:rgba(227,179,65,.18);color:var(--warn)} .b-err{background:rgba(248,81,73,.16);color:var(--err)}
    .rec li{margin-bottom:6px}
    @media (max-width:980px){.grid{grid-template-columns:repeat(2,1fr)} .layout{grid-template-columns:1fr}}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="head">
      <div>
        <div class="title">Network Diagnostic Dashboard</div>
        <div class="sub" id="meta"></div>
      </div>
      <div id="globalBadge" class="badge"></div>
    </div>
    <div class="grid">
      <div class="card"><div class="k">Score</div><div class="v acc" id="kScore">-</div></div>
      <div class="card"><div class="k">Tests OK</div><div class="v ok" id="kOk">-</div></div>
      <div class="card"><div class="k">Warnings</div><div class="v warn" id="kWarn">-</div></div>
      <div class="card"><div class="k">Errors</div><div class="v err" id="kErr">-</div></div>
      <div class="card"><div class="k">Latency Under Load</div><div class="v" id="kLatency">N/A</div></div>
    </div>
    <div class="layout">
      <div class="panel">
        <h3>Tests</h3>
        <table><thead><tr><th>Test</th><th>Cible</th><th>Statut</th><th>Detail</th></tr></thead><tbody id="testsBody"></tbody></table>
      </div>
      <div class="panel">
        <h3>Network Load (Before / Under / After)</h3>
        <table><thead><tr><th>Phase</th><th>Avg (ms)</th><th>Max (ms)</th><th>Loss (%)</th></tr></thead><tbody id="loadBody"></tbody></table>
      </div>
    </div>
    <div class="layout">
      <div class="panel">
        <h3>Configuration reseau</h3>
        <table><tbody id="netBody"></tbody></table>
      </div>
      <div class="panel">
        <h3>Recommandations</h3>
        <ul class="rec" id="recList"></ul>
      </div>
    </div>
  </div>
  <script id="diag-data" type="application/json">$jsonData</script>
  <script>
    const d = JSON.parse(document.getElementById("diag-data").textContent);
    const statusClass = s => s==="OK"||s==="HEALTHY"?"b-ok":(s==="WARNING"||s==="AVERTISSEMENT"?"b-warn":"b-err");
    const safe = v => v===null||v===undefined||v===""?"N/A":v;
    document.getElementById("meta").textContent = `${safe(d.Metadata.ComputerName)} • ${safe(d.Network.InterfaceAlias)} • ${safe(d.Network.LocalIPv4)} • ${safe(d.Metadata.Timestamp)}`;
    const g = document.getElementById("globalBadge");
    g.className = "badge " + statusClass(d.Analysis.Status || d.OverallStatus); g.textContent = safe(d.Analysis.Status || d.OverallStatus);
    document.getElementById("kScore").textContent = `${safe(d.Score.Value)}/${safe(d.Score.Max)}`;
    document.getElementById("kOk").textContent = safe(d.Summary.SuccessCount);
    document.getElementById("kWarn").textContent = safe(d.Summary.WarningCount);
    document.getElementById("kErr").textContent = safe(d.Summary.FailureCount);
    document.getElementById("kLatency").textContent = d.LoadTest && d.LoadTest.UnderLoad ? `${safe(d.LoadTest.UnderLoad.AverageLatencyMs)} ms` : "N/A";
    const testsBody = document.getElementById("testsBody");
    (d.Tests || []).forEach(t => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${safe(t.Test)}</td><td>${safe(t.Cible)}</td><td><span class="badge ${statusClass(t.Statut)}">${safe(t.Statut)}</span></td><td>${safe(t.Detail)}</td>`;
      testsBody.appendChild(tr);
    });
    const loadBody = document.getElementById("loadBody");
    [["Before", d.LoadTest?.Before], ["Under", d.LoadTest?.UnderLoad], ["After", d.LoadTest?.After]].forEach(([n,v]) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${n}</td><td>${safe(v?.AverageLatencyMs)}</td><td>${safe(v?.MaxLatencyMs)}</td><td>${safe(v?.PacketLossPercent)}</td>`;
      loadBody.appendChild(tr);
    });
    const netRows = [
      ["IPv4", d.Network.LocalIPv4], ["Masque", d.Network.SubnetMask], ["Passerelle", d.Network.Gateway],
      ["DNS", (d.Network.DnsServers||[]).join(", ")], ["DHCP", d.Network.DhcpEnabled], ["MAC", d.Network.MacAddress],
      ["Wi-Fi SSID", d.Wifi?.Ssid], ["TCP Target", d.Ports?.Target], ["TCP Open/Closed", `${safe(d.Ports?.OpenCount)}/${safe(d.Ports?.ClosedCount)}`]
    ];
    const netBody = document.getElementById("netBody");
    netRows.forEach(([k,v]) => { const tr=document.createElement("tr"); tr.innerHTML=`<th>${k}</th><td>${safe(v)}</td>`; netBody.appendChild(tr); });
    const recList = document.getElementById("recList");
    (d.Analysis?.Recommendations || ["Aucune recommendation."]).forEach(r => { const li=document.createElement("li"); li.textContent=r; recList.appendChild(li); });
  </script>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
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
$loadTestResult = Invoke-ControlledNetworkLoadTest -LoadTarget $LoadTestTarget -MonitorTarget $LoadTestMonitorTarget -SampleCount $LoadTestSampleCount -DurationSec $LoadTestDurationSec -ParallelStreams $LoadTestParallelStreams
$bandwidthResult = Invoke-BandwidthDiagnostic -Enabled:$EnableBandwidthTest -TestUrl $BandwidthTestUrl -TimeoutSec $BandwidthTimeoutSec

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$diagnosticResult = New-DiagnosticResult -DnsServerValue $DnsServer -InternetHostValue $InternetHost -PingCountValue $PingCount
$diagnosticResult.Parameters.DnsTestDomains = @($DnsTestDomains)
$diagnosticResult.Parameters.RoutingTraceTarget = $RoutingTraceTarget
$diagnosticResult.Parameters.TraceMaxHops = $TraceMaxHops
$diagnosticResult.Parameters.TcpTarget = $effectiveTcpTarget
$diagnosticResult.Parameters.TcpPorts = @($TcpPorts)
$diagnosticResult.Parameters.TcpTimeoutMs = $TcpTimeoutMs
$diagnosticResult.Parameters.IncludeWifiScan = [bool]$IncludeWifiScan
$diagnosticResult.Parameters.LoadTestTarget = $LoadTestTarget
$diagnosticResult.Parameters.LoadTestMonitorTarget = $LoadTestMonitorTarget
$diagnosticResult.Parameters.LoadTestSampleCount = $LoadTestSampleCount
$diagnosticResult.Parameters.LoadTestDurationSec = $LoadTestDurationSec
$diagnosticResult.Parameters.LoadTestParallelStreams = $LoadTestParallelStreams
$diagnosticResult.Parameters.EnableBandwidthTest = [bool]$EnableBandwidthTest
$diagnosticResult.Parameters.BandwidthTestUrl = $BandwidthTestUrl
$diagnosticResult.Parameters.BandwidthTimeoutSec = $BandwidthTimeoutSec
$diagnosticResult.Parameters.GenerateDashboard = [bool]$GenerateDashboard
$diagnosticResult.Parameters.OpenDashboard = [bool]$OpenDashboard
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
$diagnosticResult.LoadTest = $loadTestResult
$diagnosticResult.Bandwidth = $bandwidthResult

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

Write-Host "`n[10] Test charge reseau controlee :" -ForegroundColor Yellow
$loadTest = [PSCustomObject]@{
    Test              = "Network Load"
    Cible             = "$LoadTestTarget (monitor: $LoadTestMonitorTarget)"
    Statut            = $loadTestResult.Status
    Detail            = $loadTestResult.Detail
    AttemptCount      = $LoadTestSampleCount
    SuccessCount      = $loadTestResult.UnderLoad.SuccessCount
    PacketLossPercent = $loadTestResult.UnderLoad.PacketLossPercent
    AverageLatencyMs  = $loadTestResult.UnderLoad.AverageLatencyMs
    MaxLatencyMs      = $loadTestResult.UnderLoad.MaxLatencyMs
}
Write-Host "$($loadTest.Statut) - $($loadTest.Detail)"
Write-Host "Before : avg $($loadTestResult.Before.AverageLatencyMs) ms / loss $($loadTestResult.Before.PacketLossPercent)%"
Write-Host "Under  : avg $($loadTestResult.UnderLoad.AverageLatencyMs) ms / max $($loadTestResult.UnderLoad.MaxLatencyMs) ms / loss $($loadTestResult.UnderLoad.PacketLossPercent)%"
Write-Host "After  : avg $($loadTestResult.After.AverageLatencyMs) ms / loss $($loadTestResult.After.PacketLossPercent)%"
Write-Host "Delta avg/max : $($loadTestResult.AvgLatencyDeltaMs) / $($loadTestResult.MaxLatencyDeltaMs) ms"
$diagnosticResult.Tests += $loadTest

Write-Host "`n[11] Test debit reseau :" -ForegroundColor Yellow
$bandwidthTest = [PSCustomObject]@{
    Test              = "Bandwidth"
    Cible             = $BandwidthTestUrl
    Statut            = $bandwidthResult.Status
    Detail            = $bandwidthResult.Detail
    AttemptCount      = if ($EnableBandwidthTest) { 1 } else { 0 }
    SuccessCount      = if ($bandwidthResult.Status -eq "OK") { 1 } else { 0 }
    PacketLossPercent = $null
    AverageLatencyMs  = $null
    MaxLatencyMs      = $null
}
if ($bandwidthResult.Status -eq "OK") {
    Write-Host "OK - Download ~ $($bandwidthResult.DownloadMbps) Mbps ($($bandwidthResult.DownloadBytes) octets en $($bandwidthResult.DurationMs) ms)"
}
else {
    Write-Host "$($bandwidthResult.Status) - $($bandwidthResult.Detail)"
}
$diagnosticResult.Tests += $bandwidthTest

$diagnosticResult.Summary.SuccessCount = @($diagnosticResult.Tests | Where-Object { $_.Statut -eq "OK" }).Count
$diagnosticResult.Summary.FailureCount = @($diagnosticResult.Tests | Where-Object { $_.Statut -eq "ECHEC" }).Count
$diagnosticResult.Summary.WarningCount = @($diagnosticResult.Tests | Where-Object { $_.Statut -eq "AVERTISSEMENT" }).Count
$analysisResult = Get-DiagnosticAnalysis -ResultObject $diagnosticResult
$scoreResult = Get-DiagnosticScore -ResultObject $diagnosticResult
$diagnosticResult.Analysis = $analysisResult
$diagnosticResult.Score = $scoreResult
$overallStatus = $analysisResult.Status

Write-Host "`n=== DIAGNOSTIC FINAL ===" -ForegroundColor Cyan
Write-Host "Etat global : $overallStatus"
Write-Host "Score : $($scoreResult.Value)/$($scoreResult.Max) ($($scoreResult.Level))"
Write-Host "Succes : $($diagnosticResult.Summary.SuccessCount) | Avertissements : $($diagnosticResult.Summary.WarningCount) | Echecs : $($diagnosticResult.Summary.FailureCount)"
Write-Host "Analyse : $($analysisResult.Detail)"
if (@($analysisResult.Recommendations).Count -gt 0) {
    Write-Host "Recommandation principale : $($analysisResult.Recommendations[0])"
}

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
    "- $($loadTest.Test) [$($loadTest.Cible)] : $($loadTest.Statut) - $($loadTest.Detail)",
    "- $($bandwidthTest.Test) [$($bandwidthTest.Cible)] : $($bandwidthTest.Statut) - $($bandwidthTest.Detail)",
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
    "[7] Network load details",
    "Charge cible : $LoadTestTarget",
    "Cible mesure : $LoadTestMonitorTarget",
    "Duree / streams : ${LoadTestDurationSec}s / $LoadTestParallelStreams",
    "Before : avg $($loadTestResult.Before.AverageLatencyMs) ms, max $($loadTestResult.Before.MaxLatencyMs) ms, loss $($loadTestResult.Before.PacketLossPercent)%",
    "Under  : avg $($loadTestResult.UnderLoad.AverageLatencyMs) ms, max $($loadTestResult.UnderLoad.MaxLatencyMs) ms, loss $($loadTestResult.UnderLoad.PacketLossPercent)%",
    "After  : avg $($loadTestResult.After.AverageLatencyMs) ms, max $($loadTestResult.After.MaxLatencyMs) ms, loss $($loadTestResult.After.PacketLossPercent)%",
    "Delta avg/max : $($loadTestResult.AvgLatencyDeltaMs) / $($loadTestResult.MaxLatencyDeltaMs) ms",
    "Statut : $($loadTestResult.Status) - $($loadTestResult.Detail)",
    "",
    "[8] Bandwidth details",
    "Active : $([bool]$EnableBandwidthTest)",
    "URL : $BandwidthTestUrl",
    "Download (Mbps) : $(if ($bandwidthResult.DownloadMbps -ne $null) { $bandwidthResult.DownloadMbps } else { 'N/A' })",
    "Donnees lues (octets) : $(if ($bandwidthResult.DownloadBytes -ne $null) { $bandwidthResult.DownloadBytes } else { 'N/A' })",
    "Duree (ms) : $(if ($bandwidthResult.DurationMs -ne $null) { $bandwidthResult.DurationMs } else { 'N/A' })",
    "Statut : $($bandwidthResult.Status) - $($bandwidthResult.Detail)",
    "",
    "[9] Resume",
    "Etat global : $overallStatus",
    "Score : $($scoreResult.Value)/$($scoreResult.Max) ($($scoreResult.Level))",
    "Succes : $($diagnosticResult.Summary.SuccessCount)",
    "Echecs : $($diagnosticResult.Summary.FailureCount)",
    "Avertissements : $($diagnosticResult.Summary.WarningCount)",
    "",
    "[10] Analyse",
    "Statut analyse : $($analysisResult.Status)",
    "Detail : $($analysisResult.Detail)",
    "",
    "[11] ipconfig /all",
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

if (@($analysisResult.Findings).Count -gt 0) {
    $reportLines += ""
    $reportLines += "[Findings]"
    $reportLines += @($analysisResult.Findings)
}

if (@($analysisResult.Recommendations).Count -gt 0) {
    $reportLines += ""
    $reportLines += "[Recommendations]"
    $reportLines += @($analysisResult.Recommendations)
}

$stopwatch.Stop()
$diagnosticResult.Metadata.DurationMs = $stopwatch.ElapsedMilliseconds
$diagnosticResult | Add-Member -MemberType NoteProperty -Name OverallStatus -Value $overallStatus -Force

$reportLines | Out-File -FilePath $reportFile -Encoding UTF8
ipconfig /all | Out-File -FilePath $reportFile -Append -Encoding UTF8
$diagnosticResult | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonReportFile -Encoding UTF8
if ($GenerateDashboard) {
    New-DiagnosticDashboardHtml -ResultObject $diagnosticResult -OutputPath $htmlReportFile
}

Write-Host "`n[12] Sauvegarde du rapport..." -ForegroundColor Yellow
Write-Host "Diagnostic termine. Rapport TXT sauvegarde : $reportFile" -ForegroundColor Green
Write-Host "Rapport JSON sauvegarde : $jsonReportFile" -ForegroundColor Green
if ($GenerateDashboard) {
    Write-Host "Dashboard HTML sauvegarde : $htmlReportFile" -ForegroundColor Green
    if ($OpenDashboard) {
        Start-Process $htmlReportFile
    }
}
