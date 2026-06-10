# THIS MODULE WILL BE USED TO FIND LOCAL DEVICES VIA PROTOCOLS



# UI IMPORTS
from rich.live import Live


# ETC IMPORTS
from scapy.all import sniff, IP, UDP, DNS, DNSRR, Raw, send, DNSQR
import threading, time


# NSM MODULES
from vars import Variables


# CONSTANTS
console = Variables.console
table   = Variables.table
panel   = Variables.panel
PORT_MDNS  = 5353
PORT_SSDP  = 1900
FILTER     = "udp port 5353 or udp port 1900 or udp dst port 32000"


class LAN_Sniffer():
    """This class will be responsible for scanning/sniffing for mdns/* protocol traffic"""


    APPLE_KEYS   = ["_airplay._tcp", "_homekit._tcp", "_hap._tcp", "_raop._tcp", "_apple-mobdev2._tcp"]
    GOOGLE_KEYS  = ["_googlecast._tcp", "dial-multiscreen-org", "google", "chromecast"]
    AMAZON_KEYS  = ["_amzn-wplay._tcp", "amazon", "alexa"]
    ROKU_KEYS    = ["roku:ecp", "uuid:roku", "_roku-ecp._tcp", "roku-ecp", "roku"]
    SAMSUNG_KEYS = ["samsung", "urn:samsung.com", "tizen", "samsungmrdesc"]


    @classmethod
    def _categorize(cls, *fields):
        """Checks fields against known keywords and increments the right counter"""


        combined = " ".join(str(f) for f in fields if f).lower()

        if   any(k in combined for k in cls.APPLE_KEYS):   Variables.dev_apples  += 1
        elif any(k in combined for k in cls.GOOGLE_KEYS):  Variables.dev_google  += 1
        elif any(k in combined for k in cls.AMAZON_KEYS):  Variables.dev_amazon  += 1
        elif any(k in combined for k in cls.ROKU_KEYS):    Variables.dev_roku    += 1
        elif any(k in combined for k in cls.SAMSUNG_KEYS): Variables.dev_samsung += 1
        else:                                              Variables.dev_unknown += 1

        Variables.dev_total += 1

    
    
    @classmethod
    def _query_pkts(cls):
        """This will send out a ssdp request, resulting in devices respondng back"""

        
        payload = (
          "M-SEARCH * HTTP/1.1\r\n"                                                                                                                                                                     
          "HOST: 239.255.255.250:1900\r\n"                  
          "MAN: \"ssdp:discover\"\r\n"                                                                                                                                                                  
          "MX: 3\r\n"                                       
          "ST: ssdp:all\r\n"
          "\r\n"                                                                                                                                                                                        
        )  

        pkt_mdns = (                                                                                                                                                                                           
          IP(dst="224.0.0.251") /         
          UDP(sport=5353, dport=5353) /                                                                                                                                                                 
          DNS(rd=0, qd=DNSQR(qname="_services._dns-sd._udp.local", qtype="PTR"))                                                                                                                        
      )  

        pkt_ssdp = IP(dst="239.255.255.250")/UDP(sport=32000, dport=1900)/Raw(load=payload.encode())
        
        time.sleep(1)
        console.print("\n[bold cyan][+] mDNS Query  →  224.0.0.251:5353")
        console.print("[bold cyan][+] SSDP Query  →  239.255.255.250:1900\n")

        while True:
            send(pkt_mdns, verbose=False)
            send(pkt_ssdp, verbose=False)
            time.sleep(Variables.packet_sleep)



    @classmethod
    def _parse_ssdp(cls, pkt, verbose=False):
        """This will be used to parse ssdp""" 


        if Raw not in pkt: return False
        
        text   = pkt[Raw].load.decode(errors="ignore")
        fields = {}

        if "ssdp" not in text.lower() and "upnp" not in text.lower() and "http/1.1 200" not in text.lower(): return False


        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        port_src = pkt[UDP].sport
        port_dst = pkt[UDP].dport


        for line in text.splitlines():

            if ":" in line:
                
                key, value = line.split(":", 1)
                fields[key.strip().lower()] = value.strip()
        

        type     = fields.get("st") or fields.get("nt", False)
        location = fields.get("location", False)
        server   = fields.get("server",   False)
        usn      = fields.get("usn",      False)

        

        Variables.pkts +=1
        device = {
            "#": Variables.pkts,
            "Proto": "SSDP",
            "ip_src": f"{ip_src}:{port_src}",
            "ip_dst": f"{ip_dst}:{port_dst}",
            "type": type,
            "location": location,
            "server": server,
            "usn": usn
        }
        if not any([type, server, usn]): return False

        if ip_src not in Variables.ip_srcs:
            Variables.ip_srcs.append(ip_src)
            cls._categorize(type, server, usn)
            Variables.dev_ssdp += 1
            console.print(f"\n[bold green][+] New SSDP Device\n[bold cyan]    IP       [white]→  {ip_src}\n[bold cyan]    Type     [white]→  {type}\n[bold cyan]    Server   [white]→  {server}\n[bold cyan]    USN      [white]→  {usn}\n[bold cyan]    Location [white]→  {location}\n")

        else: console.print(f"[dim][~] SSDP\n    IP       →  {ip_src}\n    Type     →  {type}\n    Server   →  {server}\n    USN      →  {usn}\n    Location →  {location}")

        c1 = "bold red"
        c2 = "bold yellow"
        c3 = "bold green"

        panel.renderable = (f"[bold magenta]Total Devices:[/bold magenta] [bold white]{Variables.dev_total}[/bold white]  -  [bold magenta]Packets:[/bold magenta] [bold white]{Variables.pkts}[/bold white]  -  [{c3}]Developed by NSM Barii[/{c3}]"
                    f"\n                             [{c1}]mDNS:[/{c1}] [{c2}]{Variables.dev_mdns}[/{c2}]  -  [{c1}]SSDP:[/{c1}] [{c2}]{Variables.dev_ssdp}[/{c2}]"
                    f"\n[{c1}]Apple:[/{c1}] [{c2}]{Variables.dev_apples}[/{c2}]  -  [{c1}]Roku:[/{c1}] [{c2}]{Variables.dev_roku}[/{c2}]  -  [{c1}]Google:[/{c1}] [{c2}]{Variables.dev_google}[/{c2}]  -  [{c1}]Amazon:[/{c1}] [{c2}]{Variables.dev_amazon}[/{c2}]  -  [{c1}]Samsung:[/{c1}] [{c2}]{Variables.dev_samsung}[/{c2}]  -  [{c1}]Unknown:[/{c1}] [{c2}]{Variables.dev_unknown}[/{c2}]"
                    )


    @classmethod
    def _parse_mdns(cls, pkt, verbose=False):
        """This will be used to parse mdns"""


        if DNS not in pkt: return False
        if IP not in pkt: return False

        dns = pkt[DNS]
        question = False
        name     = False
        data     = False

        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst

        port_src = pkt[UDP].sport
        port_dst = pkt[UDP].dport


        if dns.qd:

            try: question = dns.qd.qname.decode(errors="ignore")
            except Exception: pass
        

        names = []
        datas = []

        for i in range(dns.ancount):

            ans = dns.an[i]

            if isinstance(ans, DNSRR):

                try:    names.append(ans.rrname.decode(errors="ignore"))
                except: names.append(str(ans.rrname))

                datas.append(str(ans.rdata))

        name = " ".join(names) if names else False
        data = " ".join(datas) if datas else False

        if not any([question, name, data]): return False

        Variables.pkts +=1
        device = {
            "#": Variables.pkts,
            "proto": "mDNS",
            "ip_src": f"{ip_src}:{port_src}",
            "ip_dst": f"{ip_dst}:{port_dst}",
            "question": question,
            "name": name,
            "data": data
        }
        if ip_src not in Variables.ip_srcs:
            Variables.ip_srcs.append(ip_src)
            cls._categorize(question, name, data)
            Variables.dev_mdns += 1
            console.print(f"\n[bold green][+] New mDNS Device\n[bold cyan]    IP       [white]→  {ip_src}\n[bold cyan]    Question [white]→  {question}\n[bold cyan]    Name     [white]→  {name}\n[bold cyan]    Data     [white]→  {data}\n")

        else: console.print(f"[dim][~] mDNS\n    IP       →  {ip_src}\n    Question →  {question}\n    Name     →  {name}\n    Data     →  {data}")

        c1 = "bold red"
        c2 = "bold yellow"
        c3 = "bold green"

        panel.renderable = (f"[bold magenta]Total Devices:[/bold magenta] [bold white]{Variables.dev_total}[/bold white]  -  [bold magenta]Packets:[/bold magenta] [bold white]{Variables.pkts}[/bold white]  -  [{c3}]Developed by NSM Barii[/{c3}]"
                f"\n                             [{c1}]mDNS:[/{c1}] [{c2}]{Variables.dev_mdns}[/{c2}]  -  [{c1}]SSDP:[/{c1}] [{c2}]{Variables.dev_ssdp}[/{c2}]"
                f"\n[{c1}]Apple:[/{c1}] [{c2}]{Variables.dev_apples}[/{c2}]  -  [{c1}]Roku:[/{c1}] [{c2}]{Variables.dev_roku}[/{c2}]  -  [{c1}]Google:[/{c1}] [{c2}]{Variables.dev_google}[/{c2}]  -  [{c1}]Amazon:[/{c1}] [{c2}]{Variables.dev_amazon}[/{c2}]  -  [{c1}]Samsung:[/{c1}] [{c2}]{Variables.dev_samsung}[/{c2}]  -  [{c1}]Unknown:[/{c1}] [{c2}]{Variables.dev_unknown}[/{c2}]"
                )


    @classmethod
    def _handle_pkt(cls, pkt):
        """This will be used to segment where a pkt will go"""


        def go(pkt):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport


            if sport == PORT_SSDP or dport == PORT_SSDP:   cls._parse_ssdp(pkt=pkt)
            elif dport == PORT_MDNS or sport == PORT_MDNS: cls._parse_mdns(pkt=pkt)


        threading.Thread(target=go, args=(pkt,), daemon=True).start()
    

    
    @classmethod
    def main(cls):
        """This will launch sniffer"""


        console.print(
            "\n[bold green][+] Sniffing mDNS and SSDP traffic!"
            f"\n   - mDNS: {PORT_MDNS}"
            f"\n   - SSDP: {PORT_SSDP}\n"
        )

        threading.Thread(target=cls._query_pkts, args=(), daemon=True).start()
        
        with Live(panel, console=console, refresh_per_second=4):

            sniff(filter=FILTER, prn=cls._handle_pkt, store=False)
        





if __name__ == "__main__": LAN_Sniffer.main()


