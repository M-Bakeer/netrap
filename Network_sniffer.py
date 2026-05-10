from collections import Counter
import sys
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, sniff
from Analyzer import Analyzer
import argparse



class Sniffer(Analyzer):

    def __init__(self, path=None, count=None , iface= None, timeout= None):
        super().__init__()
        self.iface= iface
        self.timeout= timeout
        
        self.count= count
        self.raw= []
        self.path= path


    def capture(self):
        try:
            if not self.count and not self.timeout:
                print("No count or timeout set, Press Ctrl+C To Stop!")

            self.raw= sniff(count= self.count or 0, iface= self.iface, timeout= self.timeout, prn=self._process)
        except PermissionError:
            print("Error: Root/admin privileges required for live capture")
        except Exception as e:
            print("Error capturing packets: ", e)


    def read(self):
        try:
            self.raw= rdpcap(self.path)
            if self.count:
                self.raw= self.raw[:self.count]

            for pkt in self.raw:
                self._process(pkt)
        except FileNotFoundError:
          print(f"Error: File {self.path} not found")
        except Exception as e:
           print("Error reading file: ",e)


    def _process(self,pkt):
            
        pkt_data={}

        if pkt.haslayer(IP):
            pkt_data['src_ip']= pkt[IP].src
            pkt_data['dst_ip']= pkt[IP].dst
        else:
            pkt_data['src_ip']= None
            pkt_data['dst_ip']= None

        if pkt.haslayer(TCP):
            protocol= "TCP"
        elif pkt.haslayer(UDP):
            protocol= "UDP"
        elif pkt.haslayer(ICMP):
            protocol= "ICMP"
        else:
            protocol= "OTHER"

        pkt_data['protocol']= protocol
        pkt_data['src_port']= None
        pkt_data['dst_port']= None

        if protocol in ["TCP", "UDP"]:
            pkt_data['src_port']= pkt[protocol].sport
            pkt_data['dst_port']= pkt[protocol].dport

        pkt_data["size"]= len(pkt)
        pkt_data["timestamp"]= pkt.time

        self.packets.append(pkt_data)
        self.pkt_num= len(self.packets)
        self._dos(pkt)

    @staticmethod
    def CLI():
        parser= argparse.ArgumentParser(description="Sniffer CLI")
        parser.add_argument("-i", "--iface", help="Network interface")
        parser.add_argument("-f", "--file", help="Path to PCAP file")
        parser.add_argument("-c", "--count", type=int, help="Number of packets")
        parser.add_argument("-t", "--timeout", type=int, help="Timeout in seconds")
        
        if len(sys.argv) == 1:
            parser.print_help()
            sys.exit(1)

        args= parser.parse_args()
        
        sniffer= Sniffer(path=args.file, count=args.count, iface=args.iface, timeout=args.timeout)
        sniffer.run()
   
        
    def run(self):
        if self.path:
            self.read()
        else:
            self.capture()
        self.analyze()
        self.report()
 


if __name__ == "__main__":
    Sniffer.CLI()
