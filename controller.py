from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP
from async_sniff import sniff
from cpu_metadata import CPUMetadata
import time

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002

class MacLearningController(Thread):
    def __init__(self, sw, start_wait=0.3):
        super(MacLearningController, self).__init__()
        self.sw = sw
        self.start_wait = start_wait # time to wait for the controller to be listening
        self.iface = sw.intfs[1].name
        self.mac_for_ip = {}
        self.port_for_mac = {}
        self.stop_event = Event()

    def addIpAddr(self, ip, mac):
        # Don't re-add the ip-mac mapping if we already have it:
        if ip in self.mac_for_ip: return

        self.sw.insertTableEntry(table_name='MyIngress.cam_table',
                match_fields={'next_hop_ip': [ip]},
                action_name='MyIngress.find_next_hop_mac',
                action_params={'dstAddr': mac})
        self.mac_for_ip[ip] = mac 

    def addMacAddr(self, mac, port):
        # Don't re-add the mac-port mapping if we already have it:
        if mac in self.port_for_mac: return

        self.sw.insertTableEntry(table_name='MyIngress.fwd_l2',
                match_fields={'hdr.ethernet.dstAddr': [mac]},
                action_name='MyIngress.set_egr',
                action_params={'port': port})
        self.port_for_mac[mac] = port

    def handleArpReply(self, pkt):
        self.addIpAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.send(pkt)

    def handleArpRequest(self, pkt):
        self.addIpAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.send(pkt)

    def handlePkt(self, pkt):
        #pkt.show2()
        assert CPUMetadata in pkt, "Should only receive packets from switch with special header"
        #print(self.sw.readCounter(counter_name='MyIngress.packet_counter', index=1))

        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1: return

        if ARP in pkt:
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)

    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)

    def run(self):
        sniff(iface=self.iface, prn=self.handlePkt, stop_event=self.stop_event)

    def start(self, *args, **kwargs):
        super(MacLearningController, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(MacLearningController, self).join(*args, **kwargs)
