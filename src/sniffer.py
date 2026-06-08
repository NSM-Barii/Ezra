# THIS MODULE WILL BE USED TO FIND LOCAL DEVICES VIA PROTOCOLS



# ETC IMPORTS
from scapy.all import sniff, IP, UDP, DNS, DNSRR, Raw
import threading


# NSM MODULES
from vars import Variables


# CONSTANTS
console = Variables.console
table   = Variables.table
PORT_MDNS  = 5353
PORT_SSDP  = 1900
FILTER     = "udp port 5353 or udp port 1900"


class LAN_Sniffer():
    """This class will be responsible for scanning/sniffing for mdns/* protocol traffic"""

    

    @classmethod
    def _parse_ssdp(cls, pkt, verbose=False):
        """This will be used to parse ssdp""" 


        if Raw not in pkt: return False
        
        text   = pkt[Raw].load.decode(errors="ignore")
        fields = {}

        if "ssdp" not in text.lower() and "upnp" not in text.lower(): return False


        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        port_src = pkt[UDP].sport
        port_dst = pkt[UDP].dport

        console.print(f"[yellow][+] Raw PKT:[/yellow] {text}")

        for line in text.splitlines():

            if ":" in line:
                
                key, value = line.split(":", 1)
                fields[key.strip().lower()] = value.strip()
        

        type     = fields.get("st") or fields.get("nt", False)
        location = fields.get("location", False)
        server   = fields.get("server",   False)
        usn      = fields.get("usn",      False)


        Variables.num +=1 
        device = {
            "#": Variables.num,
            "Proto": "SSDP",
            "ip_src": ip_src,
            "port_src": port_src,
            "ip_dst": ip_dst,
            "port_dst": port_dst,
            "type": type,
            "location": location,
            "server": server,
            "usn": usn
        }

        console.print(device)
    


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

            try:

                question = dns.qd.qname.decode(errors="ignore")

            except Exception: pass
        

        for i in range(dns.ancount):

            ans = dns.an[i]

            if isinstance(ans, DNSRR):

                try:

                    name = ans.rrname.decode(errors="ignore")
                
                except Exception: 
                    
                    name = str(ans.rrname)
                
                data = ans.rdata
        
        Variables.num +=1 
        device = {
            "#": Variables.num,
            "proto": "mDNS",
            "ip_src": ip_src,
            "port_src": port_src,
            "ip_dst": ip_dst,
            "port_dst": port_dst,
            "question": question,
            "name": name,
            "data": data
        }

        console.print(device)
    

    
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
            f"\nmDNS: {PORT_MDNS}"
            f"\nSSDP: {PORT_SSDP}\n"
        )
        
        sniff(filter=FILTER, prn=cls._handle_pkt, store=False)
        





if __name__ == "__main__": LAN_Sniffer.main()


