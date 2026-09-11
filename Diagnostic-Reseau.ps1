#requires -Version 5.1

[CmdletBinding()]
param(
    [string]$DnsServer = "8.8.8.8",
    [string]$InternetHost = "google.com",
    [int]$PingCount = 2
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
        }
        Network    = [PSCustomObject]@{
            LocalIPv4       = "Non detectee"
            Gateway         = "Non detectee"
            InterfaceAlias  = "Non detectee"
            InterfaceStatus = "Non detectee"
        }
        Tests      = @()
        Summary    = [PSCustomObject]@{
            SuccessCount = 0
            FailureCount = 0
            WarningCount = 0
        }
    }
}

# Récupération de l'interface active (IPv4)
$activeConfig = Get-NetIPConfiguration |
    Where-Object { $_.IPv4Address -and $_.NetAdapter.Status -eq "Up" } |
    Select-Object -First 1

$localIp = if ($activeConfig) { $activeConfig.IPv4Address.IPAddress } else { "Non detectee" }
$gateway = if ($activeConfig -and $activeConfig.IPv4DefaultGateway) { $activeConfig.IPv4DefaultGateway.NextHop } else { "Non detectee" }
$interfaceAlias = if ($activeConfig) { $activeConfig.InterfaceAlias } else { "Non detectee" }
$interfaceStatus = if ($activeConfig -and $activeConfig.NetAdapter) { $activeConfig.NetAdapter.Status } else { "Non detectee" }

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$diagnosticResult = New-DiagnosticResult -DnsServerValue $DnsServer -InternetHostValue $InternetHost -PingCountValue $PingCount
$diagnosticResult.Network.LocalIPv4 = $localIp
$diagnosticResult.Network.Gateway = $gateway
$diagnosticResult.Network.InterfaceAlias = $interfaceAlias
$diagnosticResult.Network.InterfaceStatus = $interfaceStatus

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
Write-Host "Passerelle : $gateway"

Write-Host "`n[2] Test connexion Internet ($InternetHost) :" -ForegroundColor Yellow
$internetTest = Test-NetworkTarget -Target $InternetHost -Label "Connexion Internet"
Write-Host "$($internetTest.Statut) - $($internetTest.Detail)"
$diagnosticResult.Tests += $internetTest

Write-Host "`n[3] Test passerelle ($gateway) :" -ForegroundColor Yellow
$gatewayTest = Test-NetworkTarget -Target $gateway -Label "Passerelle"
Write-Host "$($gatewayTest.Statut) - $($gatewayTest.Detail)"
$diagnosticResult.Tests += $gatewayTest

Write-Host "`n[4] Test DNS ($DnsServer) :" -ForegroundColor Yellow
$dnsTest = Test-NetworkTarget -Target $DnsServer -Label "DNS"
Write-Host "$($dnsTest.Statut) - $($dnsTest.Detail)"
$diagnosticResult.Tests += $dnsTest

$diagnosticResult.Summary.SuccessCount = @($diagnosticResult.Tests | Where-Object { $_.Statut -eq "OK" }).Count
$diagnosticResult.Summary.FailureCount = @($diagnosticResult.Tests | Where-Object { $_.Statut -eq "ECHEC" }).Count
$diagnosticResult.Summary.WarningCount = @($diagnosticResult.Tests | Where-Object { $_.Statut -eq "AVERTISSEMENT" }).Count

# Construction du rapport
$reportLines = @(
    "=== DIAGNOSTIC RESEAU ===",
    "Date : $(Get-Date -Format \"dd/MM/yyyy HH:mm:ss\")",
    "Machine : $env:COMPUTERNAME",
    "Utilisateur : $env:USERNAME",
    "",
    "[1] Configuration locale",
    "IP locale : $localIp",
    "Passerelle : $gateway",
    "",
    "[2] Resultats des tests",
    "- $($internetTest.Test) [$($internetTest.Cible)] : $($internetTest.Statut) - $($internetTest.Detail)",
    "- $($gatewayTest.Test) [$($gatewayTest.Cible)] : $($gatewayTest.Statut) - $($gatewayTest.Detail)",
    "- $($dnsTest.Test) [$($dnsTest.Cible)] : $($dnsTest.Statut) - $($dnsTest.Detail)",
    "",
    "[3] Resume",
    "Succes : $($diagnosticResult.Summary.SuccessCount)",
    "Echecs : $($diagnosticResult.Summary.FailureCount)",
    "Avertissements : $($diagnosticResult.Summary.WarningCount)",
    "",
    "[4] ipconfig /all",
    ""
)

$stopwatch.Stop()
$diagnosticResult.Metadata.DurationMs = $stopwatch.ElapsedMilliseconds

$reportLines | Out-File -FilePath $reportFile -Encoding UTF8
ipconfig /all | Out-File -FilePath $reportFile -Append -Encoding UTF8
$diagnosticResult | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonReportFile -Encoding UTF8

Write-Host "`n[5] Sauvegarde du rapport..." -ForegroundColor Yellow
Write-Host "Diagnostic termine. Rapport TXT sauvegarde : $reportFile" -ForegroundColor Green
Write-Host "Rapport JSON sauvegarde : $jsonReportFile" -ForegroundColor Green
