# Blocking mDNS & SSDP on GL.iNet Flint 2 (GL-MT6000)
### Developed by NSM Barii

---

## Before You Start — Check Your Firmware

This is important. The Flint 2 has two firmware streams that use different firewall engines. The method you use depends on which one you're running.

**How to check:**
1. Log into your router at `http://192.168.8.1`
2. Go to `SYSTEM → Upgrade`
3. Look at your current firmware version

| Version | Firewall Engine | Example |
|---------|----------------|---------|
| Standard (4.x) | iptables | `4.8.4`, `4.7.2` |
| op24 stream | nftables | `4.8.3-op24` |

If your version has `op24` in it — use Method B below. Otherwise use Method A.

---

## What We're Blocking and Why

| Protocol | Port | Multicast Address | Why Block |
|----------|------|-------------------|-----------|
| mDNS | 5353/UDP | 224.0.0.251 | Stops devices announcing themselves and discovering each other on your LAN |
| SSDP | 1900/UDP | 239.255.255.250 | Stops UPnP device announcements used by smart TVs and Amazon/Roku devices |

**This will NOT affect:**
- Internet browsing
- Streaming (Netflix, YouTube, etc.)
- VPN connections
- Any outbound internet traffic

**This WILL affect:**
- AirPlay (iPhone to Apple TV)
- Chromecast discovery
- Printer auto-discovery
- Any feature that requires devices to find each other on your LAN

---

## Important Note on the GL.iNet Dashboard

The GL.iNet web dashboard (`http://192.168.8.1`) does **not** have a custom firewall rules section. It only handles port forwarding and DMZ. For any real firewall customization you must use either LuCI or SSH. Both are covered below.

---

## Method A — Standard Firmware (iptables)

### Option 1: LuCI Web Interface (Easiest)

1. Open your browser and go to:
   ```
   http://192.168.8.1:8080/cgi-bin/luci/
   ```
   Or from the GL.iNet dashboard: `SYSTEM → Advanced Settings → Go To LuCI`

2. Log in with your router password

3. Navigate to:
   ```
   Network → Firewall → Custom Rules tab
   ```

4. Paste the following rules into the text box:
   ```bash
   # Block mDNS
   iptables -I FORWARD -d 224.0.0.251 -p udp --dport 5353 -j DROP
   iptables -I INPUT -d 224.0.0.251 -p udp --dport 5353 -j DROP

   # Block SSDP
   iptables -I FORWARD -d 239.255.255.250 -p udp --dport 1900 -j DROP
   iptables -I INPUT -d 239.255.255.250 -p udp --dport 1900 -j DROP
   ```

5. Click **Restart Firewall**

These rules are written to `/etc/firewall.user` and survive reboots automatically.

---

### Option 2: SSH (If you prefer terminal)

1. SSH into your router:
   ```bash
   ssh root@192.168.8.1
   ```

2. Open `/etc/firewall.user`:
   ```bash
   vi /etc/firewall.user
   ```

3. Add the rules:
   ```bash
   # Block mDNS
   iptables -I FORWARD -d 224.0.0.251 -p udp --dport 5353 -j DROP
   iptables -I INPUT -d 224.0.0.251 -p udp --dport 5353 -j DROP

   # Block SSDP
   iptables -I FORWARD -d 239.255.255.250 -p udp --dport 1900 -j DROP
   iptables -I INPUT -d 239.255.255.250 -p udp --dport 1900 -j DROP
   ```

4. Save and apply immediately:
   ```bash
   fw3 restart
   ```

---

## Method B — op24 Firmware (nftables)

The op24 firmware uses nftables instead of iptables. The LuCI Custom Rules tab is missing on this firmware and `/etc/firewall.user` does not exist. Use this method instead.

### Option 1: LuCI Local Startup (Easiest)

1. Go to LuCI at `http://192.168.8.1:8080/cgi-bin/luci/`

2. Navigate to:
   ```
   System → Startup → Local Startup tab
   ```

3. Add the following **before** the `exit 0` line:
   ```bash
   # Block mDNS
   iptables -I FORWARD -d 224.0.0.251 -p udp --dport 5353 -j DROP
   iptables -I INPUT -d 224.0.0.251 -p udp --dport 5353 -j DROP

   # Block SSDP
   iptables -I FORWARD -d 239.255.255.250 -p udp --dport 1900 -j DROP
   iptables -I INPUT -d 239.255.255.250 -p udp --dport 1900 -j DROP
   ```

4. Click **Save**

5. Apply immediately via SSH:
   ```bash
   sh /etc/rc.local
   ```

### Option 2: SSH directly

1. SSH into your router:
   ```bash
   ssh root@192.168.8.1
   ```

2. Edit `/etc/rc.local`:
   ```bash
   vi /etc/rc.local
   ```

3. Add the rules before `exit 0`:
   ```bash
   # Block mDNS
   iptables -I FORWARD -d 224.0.0.251 -p udp --dport 5353 -j DROP
   iptables -I INPUT -d 224.0.0.251 -p udp --dport 5353 -j DROP

   # Block SSDP
   iptables -I FORWARD -d 239.255.255.250 -p udp --dport 1900 -j DROP
   iptables -I INPUT -d 239.255.255.250 -p udp --dport 1900 -j DROP
   ```

4. Apply immediately:
   ```bash
   sh /etc/rc.local
   ```

---

## Verify the Rules Are Active

After applying, confirm the rules are in place via SSH:

```bash
iptables -L FORWARD -n | grep -E "224.0.0.251|239.255.255.250"
iptables -L INPUT -n | grep -E "224.0.0.251|239.255.255.250"
```

You should see DROP rules for both multicast addresses. If the output is empty the rules are not active.

---

## Removing the Rules

If you need to undo this:

**iptables (remove immediately):**
```bash
iptables -D FORWARD -d 224.0.0.251 -p udp --dport 5353 -j DROP
iptables -D INPUT -d 224.0.0.251 -p udp --dport 5353 -j DROP
iptables -D FORWARD -d 239.255.255.250 -p udp --dport 1900 -j DROP
iptables -D INPUT -d 239.255.255.250 -p udp --dport 1900 -j DROP
```

Then remove the rules from whichever file you added them to (`/etc/firewall.user` or `/etc/rc.local`) so they don't come back on reboot.

---

## Sources

- GL.iNet Flint 2 Official Docs: https://docs.gl-inet.com/router/en/4/user_guide/gl-mt6000/
- GL.iNet Firewall Interface Guide: https://docs.gl-inet.com/router/en/4/interface_guide/firewall/
- GL.iNet Forum — Missing Custom Rules Tab: https://forum.gl-inet.com/t/flint-2-missing-fw-custom-rules-tab/37559
- GL.iNet Forum — Firmware Versions: https://forum.gl-inet.com/t/mt-6000-flint-2-firmware-versions/57139
- OpenWrt Firewall Configuration: https://openwrt.org/docs/guide-user/firewall/firewall_configuration
