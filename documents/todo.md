# Ezra — Todo
### Features to build

---

## Priority Order

**1. UPnP LOCATION XML Fetcher**
Every SSDP device broadcasts a LOCATION URL pointing to its device description XML.
Auto-fetch it, parse manufacturer + model + firmware version.
This is the most important feature — feeds directly into CVE research.
Relevant fields to extract: `manufacturer`, `modelName`, `modelNumber`, `firmwareVersion`, `serialNumber`

**2. SSDP Spoofing**
Announce fake UPnP devices to the network via crafted NOTIFY packets.
More reliable than mDNS spoofing — no conflict resolution, zero authentication.
Smart TVs and UPnP control points will add fake devices no questions asked.
Build as companion module to existing spoofer.py.

**3. CVE Lookup**
After getting model + firmware from LOCATION XML, query NVD API automatically.
Endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<model>
Display CVE count and severity in the panel alongside device info.

**4. Device Export**
Save discovered devices to JSON/CSV on demand.
Format should include: ip, protocol, brand, hostname, services, model, firmware, cves
For use with Framework and other NSM tools.

---

## Decisions Made

- **No ARP scanner** — mDNS/SSDP already surfaces interesting devices with enough context. ARP just gives IPs with no info, nmap handles it better.
- **Keep mDNS spoofing** — already built, works on non-Apple devices. Don't expand it further though — Apple is too hardened.
- **SSDP spoofing over mDNS spoofing** — more reliable, more useful, no conflict resolution to fight.
- **Stay separate from Framework** — Ezra is passive LAN intelligence, Framework is active exploitation. They feed each other, not the same tool.
