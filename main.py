from p4app import P4Mininet

from controller import MacLearningController
from my_topo import SingleSwitchTopo

# Add three hosts. Port 1 (h1) is reserved for the CPU.
N = 3

topo = SingleSwitchTopo(N)
net = P4Mininet(program="l2switch.p4", topo=topo, auto_arp=False)
net.start()

# Add a mcast group for all ports (except for the CPU port)
bcast_mgid = 1
sw = net.get("s1")
sw.addMulticastGroup(mgid=bcast_mgid, ports=range(2, N + 1))
h2, h3 = net.get("h2"), net.get("h3")

# Send MAC bcast packets to the bcast multicast group
sw.insertTableEntry(
    table_name="MyIngress.fwd_l2",
    match_fields={"hdr.ethernet.dstAddr": ["ff:ff:ff:ff:ff:ff"]},
    action_name="MyIngress.set_mgid",
    action_params={"mgid": bcast_mgid},
)

# initialize IPv4 routing table for testing
sw.insertTableEntry(table_name='MyIngress.ipv4_routing',
                    match_fields={'hdr.ipv4.dstAddr': [h2.defaultIntf().IP(), 32]},
                    action_name='MyIngress.find_next_hop_ip',
                    action_params={'dstAddr': h2.defaultIntf().IP()})

sw.insertTableEntry(table_name='MyIngress.ipv4_routing',
                    match_fields={'hdr.ipv4.dstAddr': [h3.defaultIntf().IP(), 32]},
                    action_name='MyIngress.find_next_hop_ip',
                    action_params={'dstAddr': h3.defaultIntf().IP()})

sw.insertTableEntry(table_name='MyIngress.local_ip_table',
                    match_fields={'hdr.ipv4.dstAddr': sw.defaultIntf().IP()},
                    action_name='MyIngress.send_to_cpu',
                    action_params={})

# Start the MAC learning controller
cpu = MacLearningController(sw)
cpu.start()

# start the mininet CLI to run commands interactively
#from mininet.cli import CLI
#CLI(net)

print(h2.cmd("arping -c1 10.0.0.3"))

print(h3.cmd("ping -c1 10.0.0.2"))

# These table entries were added by the CPU:
sw.printTableEntries()
