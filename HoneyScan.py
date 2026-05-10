import argparse
import sys
from scapy.all import IP, IPv6, TCP, send, sniff
from rich.console import Console
from rich.table import Table

class HoneyScanner:
    def __init__(self, ip, real_ports, honey_ports, iface):
        self.ip= ip
        self.real_ports= real_ports
        self.honey_ports= honey_ports
        self.iface= iface
        self.blocked= []
        self.suspicious= {}
        self.honey_hits= {}
        self.console= Console()
    
    def _build_response(self, p):
        if p.haslayer(IP):
            response= IP(src=p[IP].dst, dst=p[IP].src) /\
                      TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq+1)
            source= p[IP].src
        elif p.haslayer(IPv6):
            response= IPv6(src=p[IPv6].dst, dst=p[IPv6].src)/\
                      TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq+1)
            source= p[IPv6].src
        else:
            return None
        return response,source

    
    def _analyzePackets(self, p):
        result = self._build_response(p)
        if result is None:
            return

        response,source= result

        if p[TCP].flags != 'S':
            return

        if p[TCP].dport in self.honey_ports:
            response[TCP].flags= 'SA'
            self.honey_hits[p[TCP].dport]= self.honey_hits.get(p[TCP].dport, 0) + 1
            send(response,verbose=False)
            self.console.print(f"[green] Honeypot hit! Fake SYN/ACK sent to {source} on port {p[TCP].dport}[/green]")
        elif p[TCP].dport in self.real_ports:
            if source in self.blocked:
                response[TCP].flags= 'RA'
                send(response,verbose=False)
                self.console.print(f"[red] RST sent to blocked IP {source} on port {p[TCP].dport}[/red]")
            else:
                response[TCP].flags= 'SA'
                send(response,verbose=False)
                self.console.print(f"[blue] Legitimate connection allowed for {source} on port {p[TCP].dport}[/blue]")
        else:
            self.suspicious[source] = self.suspicious.get(source, 0) + 1
            self.console.print(f"[yellow] Suspicious: {source} probed unknown port {p[TCP].dport} ({self.suspicious[source]}/3)[/yellow]")
            response[TCP].flags= 'RA'
            send(response,verbose=False)
            if self.suspicious.get(source, 0) >= 10 and source not in self.blocked:
                self.blocked.append(source)
                self.console.print(f"[red bold] {source} is now blocked![/red bold]")

    def report(self):

        blocked_table= Table(title="Blocked IPs")
        blocked_table.add_column("IP", style="cyan", justify="center")
        blocked_table.add_column("Probes", style="yellow", justify="center")
        blocked_table.add_column("Blocked", style="red", justify="center")

        for ip,count in self.suspicious.items():
            if ip in self.blocked: 
                blocked="Yes"
            else: 
                blocked="No"
            blocked_table.add_row(ip, str(count), blocked)

        honey_table= Table(title="Honey Hits")
        honey_table.add_column("Port", style="cyan", justify="center")
        honey_table.add_column("Hits", style="green", justify="center")

        for port,hits in self.honey_hits.items():
            honey_table.add_row(str(port),str(hits))
        
        self.console.print("\n")
        self.console.print(blocked_table)
        self.console.print(honey_table)

    @staticmethod
    def CLI():
        parser= argparse.ArgumentParser(description="HoneyScan CLI")
        parser.add_argument("ip", help="Target IP to protect")
        parser.add_argument("-i", "--iface", help="Network interface")
        parser.add_argument("-r", "--real", help="Real ports (comma separated)")
        parser.add_argument("-hp", "--honey", help="Honey ports (comma separated)")
                    
        args= parser.parse_args()
        
        real_ports= list(map(int, args.real.split(",")))  if args.real  else []
        honey_ports= list(map(int, args.honey.split(","))) if args.honey else []

        scanner= HoneyScanner(ip=args.ip, real_ports=real_ports, honey_ports=honey_ports, iface=args.iface)
    
        try:
            scanner.run()
        except KeyboardInterrupt:
            scanner.report()
        
    
    def run(self):
        try:
            f = "dst host "+self.ip+" and tcp"
            self.console.print(f"[cyan]HoneyScanner listening on {self.iface}...[/cyan]")
            sniff(filter=f,prn=self._analyzePackets,iface=self.iface)
        except PermissionError:
            print("Error: Root/admin privileges required for live capture")
        except Exception as e:
            print("Error capturing packets: ", e)


if __name__ == "__main__":
    HoneyScanner.CLI()