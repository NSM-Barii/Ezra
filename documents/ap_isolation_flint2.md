# AP Isolation on GL.iNet Flint 2 (GL-MT6000)
### Developed by NSM Barii

---

## What AP Isolation Does

Prevents devices on the same WiFi network from communicating with each other directly. Every device can still reach the internet but cannot talk to other devices on your LAN. Phone can't see TV, TV can't see phone, etc.

This kills:
- AirPlay
- Chromecast casting
- Printer discovery
- Any local device to device communication

Internet browsing, streaming, and all outbound traffic still works normally.

---

## How To Enable

### Option 1 — GL.iNet Dashboard (Main Network)

1. Go to `http://192.168.8.1`
2. Navigate to:
   ```
   Network → LAN → Basic Settings → AP Isolation → toggle on
   ```
3. Save

### Option 2 — GL.iNet Dashboard (Guest Network)

1. Go to `http://192.168.8.1`
2. Navigate to:
   ```
   Network → Guest Network → Basic Settings → AP Isolation → toggle on
   ```
3. Save

### Option 3 — LuCI

1. Go to `http://192.168.8.1:8080/cgi-bin/luci/`
2. Navigate to:
   ```
   Network → Wireless → Edit your SSID → Advanced Settings tab → Isolate Clients → check box
   ```
3. Save and Apply

---

## Verify It Works

After enabling, try to AirPlay or cast from your phone to another device. If AP isolation is working the device will either not show up at all or fail to connect.

---

## Notes

- Enable separately for 2.4GHz and 5GHz networks if you have both
- Some sources claim MT-series MediaTek routers have driver issues with client isolation — confirmed working on the GL-MT6000 despite this
- This is a simpler solution than VLAN segmentation for basic device isolation
- Does not affect wired ethernet devices — only WiFi clients

---

## Sources

- GL.iNet LAN Interface Guide: https://docs.gl-inet.com/router/en/4/interface_guide/lan/
- GL.iNet Guest Network Guide: https://docs.gl-inet.com/router/en/4/interface_guide/guest_network/
- GL.iNet Forum — Client Isolation Discussion: https://forum.gl-inet.com/t/guest-network-isolation-is-not-working/48576
