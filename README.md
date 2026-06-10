<div align="center">
  <img src="assets/banner.svg" alt="EZRA - LAN Intelligence Suite" width="100%"/>
</div>

---

> Passive LAN intelligence — silently maps mDNS & SSDP traffic to fingerprint devices, expose privacy risks, and surface CVE targets

![Status](https://img.shields.io/badge/status-under%20development-blue?style=flat-square)

---

### *By a Star Wars Nerd*

> **"I can feel them... I can feel all of them."** - Ezra Bridger

Passive LAN intelligence tool. Listens for mDNS and SSDP traffic to silently map every device on your network — who they are, what they're broadcasting, and what that means for your privacy.

**Core Features:** mDNS Sniffing • SSDP Sniffing • Device Fingerprinting • Brand Categorization • Live Stats Panel • mDNS Spoofing • SSDP Spoofing (soon) • CVE Lookup (soon)

---

## Installation

```bash
git clone https://github.com/nsm-barii/ezra.git
cd ezra/src
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

**Run the sniffer:**
```bash
sudo venv/bin/python sniffer.py
```

**Run the spoofer:**
```bash
sudo venv/bin/python spoofer.py
```

---

## Modules

| File | Description |
|------|-------------|
| `sniffer.py` | Passive mDNS + SSDP listener — discovers and categorizes LAN devices in real time |
| `spoofer.py` | mDNS spoofer — floods LAN discovery with fake device announcements |
| `vars.py` | Shared state — console, panel, device counters |

---

## What It Detects

| Protocol | Port | Multicast | Devices |
|----------|------|-----------|---------|
| mDNS | 5353 | 224.0.0.251 | Apple, Google, Roku, IoT |
| SSDP | 1900 | 239.255.255.250 | Smart TVs, Amazon, Samsung, UPnP |

**Device fingerprinting by brand:** Apple · Google · Amazon · Roku · Samsung · Unknown

---

## Coming Soon

| Feature | Description |
|---------|-------------|
| UPnP Device Description Fetcher | Auto-fetch LOCATION XML from SSDP devices — returns exact model + firmware version for CVE research |
| SSDP Spoofing | Flood LAN with fake UPnP device announcements — more reliable than mDNS spoofing, zero conflict resolution |
| CVE Lookup | After identifying model/firmware, auto-query NVD API — Ezra tells you what CVEs exist for each discovered device |
| Device Export | Save discovered devices to file for use with other NSM tools |

---

## Why This Matters

Every device on your LAN is constantly broadcasting its identity — device name, brand, services, software version. Smart TVs screenshot what you watch every 500ms and sell it to advertisers. Amazon Echo devices port scan your network. Samsung settled with the Texas AG in 2026 for collecting ACR data without consent.

Ezra makes the invisible visible.

---

## Documentation

Full research documentation in `/documents`:

- `protocols.md` — mDNS, DNS-SD, and SSDP technical breakdown
- `protocol_evolution.md` — How every LAN discovery protocol led to the next (1983–2022)
- `big_tech_lan_harvesting.md` — Verified cases of big tech harvesting LAN data for advertising
- `blocking_mdns_ssdp_flint2.md` — How to block mDNS/SSDP on GL.iNet Flint 2
- `ap_isolation_flint2.md` — How to enable AP isolation on GL.iNet Flint 2

---

## About

Created by **NSM-Barii** - Star Wars nerd | Cybersecurity enthusiast

**NSM Toolset:**
- **Vader** - Mass IP scanning
- **Maul** - Infrastructure mapping
- **Yoda** - Passive RF monitoring
- **Ezra** - LAN intelligence (this tool)

---

**Disclaimer:** For use on networks you own or have explicit authorization to test. Unauthorized network scanning is illegal.

MIT License
