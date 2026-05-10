from scapy.all import IP, get_working_ifaces
from collections import Counter, defaultdict, deque
from rich.console import Console
from rich.table import Table

class Analyzer:

    def __init__(self):
        self.packets= []
        self.pkt_num= None
        self.proto_count= None
        self.total= Counter()
        self.ratio= 0
        self.duration= 0
        self.top_ip= None
        self.port_scan= {}

        self.pkt_times= defaultdict(deque)
        self.alerts= []


    @staticmethod
    def interfaces():
        for iface in get_working_ifaces():
            print(iface.name)

    def _dos(self, pkt):

        if pkt.haslayer(IP):
            src= pkt[IP].src
            dst= pkt[IP].dst
            timestamp= pkt.time
            self.pkt_times[src].append(timestamp)

            while self.pkt_times[src] and timestamp - self.pkt_times[src][0] > 1:
                self.pkt_times[src].popleft()

            rate= len(self.pkt_times[src])
            if rate > 1000:
                print(f"Potential DoS attack from {src} to {dst} ({len(self.pkt_times[src])} packets in last second)")
                self.alerts.append({"src": src, "dst": dst, "rate": rate, "time": timestamp})


    def analyze(self):
        if not self.packets:
            print("No packets to analyze")
            return

        proto_list= [p['protocol'] for p in self.packets]
        self.proto_count= Counter(proto_list)

        sent_size= Counter()
        rec_size= Counter()
        start_time= float('inf')
        end_time= float('-inf')

        for p in self.packets:
            if p['src_ip']:
                sent_size[p['src_ip']] += p['size']
                rec_size[p['dst_ip']] += p['size']

            if p['timestamp'] < start_time:
                start_time= p['timestamp']
            if p['timestamp'] > end_time:
                end_time= p['timestamp']

    
        self.total= sent_size+rec_size
        self.duration= end_time - start_time

        self.top_ip, top_bytes= sent_size.most_common(1)[0]
        self.ratio= top_bytes/ self.total.total()

        for p in self.packets:
            if p['src_ip'] and p['dst_port']:
                if p['src_ip'] not in self.port_scan:
                    self.port_scan[p['src_ip']]= set() 
                self.port_scan[p['src_ip']].add(p['dst_port'])

    def _unit_converter(self, n):
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024

    def report(self):
        console= Console()
        
        console.print("==== NETWORK TRAFFIC REPORT ====\n", style="bold white")
        console.print(f"[magenta]Total Packets:[/magenta] {self.pkt_num}")
        console.print(f"[magenta]Total Bytes:[/magenta] {self._unit_converter(self.total.total())}")
        console.print(f"[magenta]Duration:[/magenta] {self.duration:.2f}")


        proto_table= Table(title="Protocol Distribution")
        proto_table.add_column("Protocol", style="cyan")
        proto_table.add_column("Count", style="green")

        for proto, count in self.proto_count.items():
            proto_table.add_row(proto, str(count))

        top_table= Table(title="Top 5 Talkers")
        top_table.add_column("IP", style="cyan", justify="center")
        top_table.add_column("Bytes", style="green")

        for ip, size in self.total.most_common(5):
            top_table.add_row(ip, self._unit_converter(size))

        sus_table= Table(title="Suspicious Activity")
        sus_table.add_column("Type", style="red", justify="center")
        sus_table.add_column("Details", style="yellow", justify="center")

        if self.ratio > 0.4:
            sus_table.add_row("High Volume", f"{self.top_ip} sent {self.ratio:.1%} of all traffic")

        for ip, ports in self.port_scan.items():
            if len(ports) > 10:
                sus_table.add_row("Port Scan", f"{ip} contacted {len(ports)} distinct ports")

        console.rule("[bold]Network Traffic Report[/bold]")
        console.print(proto_table)
        console.print(top_table)
        console.print(sus_table)
       
