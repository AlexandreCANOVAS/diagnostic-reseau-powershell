# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Changed
- Finalisation et stabilisation de la phase de démonstration.
- Harmonisation de l’interface terminal/dashboard en français.
- Ajustement de l’affichage horaire du dashboard (HH:mm:ss, sans millisecondes).
- Amélioration de robustesse du rendu dashboard local (sections réseau/recommandations remplies).
- Correction du calcul de `DurationMs` pour couvrir l’exécution complète.
- Suppression de dette technique (`Get-OverallStatus` inutilisée).
- Mise à jour documentation (README + guide technicien L1/L2).

## [2026-09-11]

### Added
- Structured diagnostic object used by terminal and reports.
- JSON report export.
- Extended network configuration diagnostics (mask, DNS, DHCP, MAC, link speed).
- DHCP diagnostics with APIPA detection and lease information.
- Advanced DNS diagnostics with multi-domain resolution and latency.
- Routing diagnostics with default route and traceroute summary.
- Targeted TCP port diagnostics with timeout control.
- Wi-Fi diagnostics with interface/signal/channel details and optional nearby scan.
- Controlled network load test (before/under/after metrics).
- Optional real download bandwidth test.
- Automatic analysis findings/recommendations and network health score.
- HTML dashboard generation from structured results.
- Improved terminal readability (sections and colored statuses).

### Changed
- Reports now include richer technical and analysis sections.
