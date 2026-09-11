# 🔧 Diagnostic Réseau PowerShell

Outil professionnel de diagnostic réseau Windows orienté **support IT / GMSI / L1-L2**.

Le point d’entrée du projet est :

```powershell
.\Diagnostic-Reseau.ps1
```

---

## 🎯 Objectif
- Exécuter un diagnostic réseau complet en une seule commande.
- Centraliser les résultats dans un modèle structuré unique.
- Afficher une vue terminal claire + générer des rapports exploitables.

## ✨ Fonctionnalités
- Configuration réseau IPv4 (IP, masque, passerelle, DNS, MAC, vitesse, interface).
- Tests de connectivité (Internet, passerelle, DNS).
- Diagnostic DHCP (serveur, bail, APIPA).
- Diagnostic DNS avancé (multi-domaines, latence, erreurs).
- Diagnostic routage (route par défaut, passerelle, traceroute).
- Tests TCP ciblés (ports configurables, timeout contrôlé).
- Diagnostic Wi-Fi (SSID, signal, canal, RX/TX, scan optionnel).
- Test de charge réseau contrôlé (avant / charge / après).
- Test de débit optionnel (téléchargement chronométré).
- Analyse automatique + recommandations + score global.
- Rapports TXT / JSON / HTML (dashboard local).

## 🧩 Architecture logique
```text
Diagnostic-Reseau.ps1
  -> Collecte diagnostics
  -> Résultats structurés
  -> Analyse + score
  -> Affichage terminal
  -> Export TXT / JSON / HTML
```

## ⚙️ Prérequis
- Windows 10/11
- Windows PowerShell 5.1+
- Accès réseau selon les tests lancés
- Droits standard (admin non obligatoire en mode normal)

## 🚀 Utilisation

### Exécution standard
```powershell
powershell -ExecutionPolicy Bypass -File .\Diagnostic-Reseau.ps1
```

### Exécution avancée (exemple)
```powershell
.\Diagnostic-Reseau.ps1 `
  -DnsServer "8.8.8.8" `
  -DnsTestDomains "google.com","github.com" `
  -RoutingTraceTarget "1.1.1.1" `
  -TraceMaxHops 3 `
  -TcpTarget "google.com" `
  -TcpPorts 80,443 `
  -IncludeWifiScan `
  -LoadTestTarget "cloudflare.com" `
  -LoadTestMonitorTarget "8.8.8.8" `
  -LoadTestSampleCount 3 `
  -LoadTestDurationSec 3 `
  -LoadTestParallelStreams 1 `
  -EnableBandwidthTest `
  -OpenDashboard
```

## 🛠️ Paramètres principaux
- `DnsServer`, `DnsTestDomains`
- `RoutingTraceTarget`, `TraceMaxHops`
- `TcpTarget`, `TcpPorts`, `TcpTimeoutMs`
- `IncludeWifiScan`
- `LoadTestTarget`, `LoadTestMonitorTarget`
- `LoadTestSampleCount`, `LoadTestDurationSec`, `LoadTestParallelStreams`
- `EnableBandwidthTest`, `BandwidthTestUrl`, `BandwidthTimeoutSec`
- `GenerateDashboard`, `OpenDashboard`

## 📄 Rapports générés
- `diagnostic_yyyy-MM-dd_HH-mm.txt`
- `diagnostic_yyyy-MM-dd_HH-mm.json`
- `diagnostic_yyyy-MM-dd_HH-mm.html`

Le **JSON** est la source structurée principale pour l’analyse et le dashboard.

## 🧪 Statuts
- `OK` : fonctionnement normal
- `AVERTISSEMENT` : vérification recommandée
- `ECHEC / CRITICAL` : incident à traiter
- `N/A` : non applicable / indisponible

## 🔐 Sécurité & limites
- Pas de scan agressif.
- Test de charge limité et contrôlé.
- Pas de secrets stockés.
- Les résultats dépendent de l’état réseau au moment du test.

## 📚 Documentation
- Guide utilisateur : `README.md`
- Guide technicien L1/L2 : `Docs/Guide-Technicien.md`
- Changelog : `CHANGELOG.md`

## 🖼️ Exemples
![Exemple sortie terminal](./Assets/Outil%20diagnostic%20r%C3%A9seau.png)
![Exemple dashboard web](./Assets/Page%20web%20diagnostic.png)
