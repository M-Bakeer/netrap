from collections import Counter, defaultdict, deque
from Network_sniffer import Sniffer
from scapy.all import IP, sniff
import time
import threading

class LiveCapture(Sniffer):

    def __init__(self, count=None, iface=None, timeout=None, filter=None):
        super().__init__(count=count, iface=iface, timeout=timeout)

        self.live_packets= 0
        self.live_proto= {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
        self.live_bytes= Counter()
        self.filter= filter
        self.start_time= None
        self._running= False
        self._session_id= 0

    def _make_processor(self, session_id):
        """Return a packet handler bound to this session. Old threads get stale session_id."""
        def process(pkt):
            if self._session_id != session_id:
                return

            super(LiveCapture, self)._process(pkt)

            # check again in case stop() fired during super()._process()
            if self._session_id != session_id:
                if self.packets:
                    self.packets.pop()
                    self.pkt_num = len(self.packets)
                return

            if self.start_time is None:
                self.start_time= time.time()

            pkt_data= self.packets[-1]
            self.live_packets += 1
            self.live_proto[pkt_data['protocol']] += 1

            if pkt.haslayer(IP):
                self.live_bytes[pkt_data['src_ip']] += pkt_data['size']

                if pkt_data['dst_port']:
                    if pkt_data['src_ip'] not in self.port_scan:
                        self.port_scan[pkt_data['src_ip']] = set()
                    self.port_scan[pkt_data['src_ip']].add(pkt_data['dst_port'])

                    if len(self.port_scan[pkt_data['src_ip']]) > 10:
                        self.alerts.append({"type": "port_scan", "src": pkt_data['src_ip'], "time": time.time()})

        return process

    def get_stats(self):
        return {
            "total_packets" : self.live_packets,
            "total_bytes"   : sum(self.live_bytes.values()),
            "proto_count"   : self.live_proto,
            "top_ips"       : [{"ip": ip, "bytes": b} for ip, b in self.live_bytes.most_common(5)],
            "duration"      : round(time.time() - self.start_time, 1) if self.start_time else 0,
            "running"       : self._running,
            "alerts"        : self.alerts
        }

    def get_alerts(self):
        return self.alerts

    def stop(self):
        self._session_id += 1
        self._running= False
        self.live_packets= 0
        self.live_proto= {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
        self.live_bytes= Counter()
        self.alerts= []
        self.packets= []
        self.pkt_num= 0
        self.port_scan= {}
        self.pkt_times= defaultdict(deque)
        self.start_time= None

    def run(self):
        self._running = True
        processor = self._make_processor(self._session_id)
        try:
            sniff(
                count= self.count or 0,
                iface= self.iface,
                timeout= self.timeout,
                filter= self.filter,
                prn= processor,
            )
        except PermissionError:
            print("Error: Root/admin privileges required for live capture")
        except Exception as e:
            print("Error capturing packets:", e)
        finally:
            self._running = False
