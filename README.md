# 🛡️ Threat Hunting Automation Dashboard

A production-grade threat hunting dashboard for Microsoft Sentinel, built for SOC analysts. Features live threat intelligence, 60+ KQL hunting queries mapped to MITRE ATT&CK, and an AI-powered hypothesis generator.

**🔗 Live Dashboard:** https://vidhicti.github.io/threat-hunt-dashboard/

## Features

### 🎯 MITRE ATT&CK Heatmap
- 95 techniques mapped across 14 tactics
- Auto-calculates coverage from your KQL query library
- Click any technique to see linked queries and live IOCs
- Color-coded by detection coverage level

### 🔍 KQL Query Library  
- 60 production KQL queries for Microsoft Sentinel
- Covers all major MITRE ATT&CK tactics
- Mapped to your exact log sources: Fortigate, Palo Alto, Sophos, MDE, AD, DNS, O365, Trend Micro
- Adjustable time range (1h → 30d)
- Copy-to-clipboard, export all as .txt

### 💡 Hypotheses & Hunt Workflow
- 8 structured hunt hypotheses with tactic chains
- Hunt workflow: Open → In Progress → True/False Positive → Closed
- Investigation notes and evidence tracking
- Hunt report export as markdown
- AI-powered live hypothesis generation (requires free Groq API key)
- Custom hypothesis generator based on your requirements

### 🌐 Live IOC Tracker
- 1200+ IOCs from 9 free threat intel feeds:
  - ThreatFox, URLhaus, FeodoTracker, MalwareBazaar
  - EmergingThreats, CINS Army, SSL Blacklist
  - AlienVault OTX, CERT Poland
- Auto-enrichment: country, ISP, ASN for IP indicators
- Per-IOC KQL generation for instant Sentinel hunting
- Watchlist KQL builder for bulk IOC correlation
- Export to CSV
- IOC whitelist management

### ⚡ KQL Generator
- AI-powered KQL generation for any MITRE TTP
- Browse queries by tactic and technique
- Bulk generation for multiple TTPs
- Requires free Groq API key (console.groq.com)

## Setup

### Quick Start (view only)
Visit https://vidhicti.github.io/threat-hunt-dashboard/ — no setup required.

### Enable AI Features (free)
1. Go to https://console.groq.com
2. Sign up with Google (free, no credit card)
3. Create an API key
4. In the dashboard → Settings → paste your Groq API key
5. Click Test to verify

### Run Locally
```bash
git clone https://github.com/vidhicti/threat-hunt-dashboard.git
cd threat-hunt-dashboard
npm install
npm run dev
```

Open http://localhost:5173

### Deploy Your Own
```bash
# Deploy frontend to GitHub Pages
npm run deploy

# Deploy API backend to Vercel (required for live IOC feeds)
vercel --prod
```

## Log Sources Supported
| Source | Sentinel Table | Coverage |
|--------|---------------|----------|
| Fortigate Firewall | CommonSecurityLog (Fortinet) | C2, Exfil, Lateral Movement |
| Palo Alto Firewall | CommonSecurityLog (Palo Alto Networks) | Threat detection, C2 |
| Sophos XG | CommonSecurityLog (Sophos) | Malware, Web filtering |
| Active Directory | SecurityEvent | Auth, Persistence, Priv Esc |
| Microsoft Defender (MDE) | DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents | Endpoint TTPs |
| DNS | ASimDnsActivityLogs | C2, Exfil, Phishing |
| Office 365 | OfficeActivity | Phishing, Data access |
| Trend Micro | CommonSecurityLog (Trend Micro) | Malware, AV events |

## Architecture
- **Frontend:** React + Vite → GitHub Pages
- **Backend API:** Vercel Serverless Functions (threat intel feed aggregation)
- **AI:** Groq API (free tier, Llama 3.3 70B)
- **Storage:** localStorage (hunt workflow, settings, IOC whitelist, enrichment cache)

## Contributing
This is a personal SOC tool. The repo is public for reference.
Issues and suggestions welcome via GitHub Issues.

## License
MIT
