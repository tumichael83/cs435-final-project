/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> mcastGrp_t;

const port_t CPU_PORT           = 0x1;

const bit<16> ARP_OP_REQ        = 0x0001;
const bit<16> ARP_OP_REPLY      = 0x0002;

const bit<16> TYPE_IPV4         = 0x0800;
const bit<16> TYPE_ARP          = 0x0806;
const bit<16> TYPE_CPU_METADATA = 0x080a;

const bit<32> CNTR_IDX_ARP      = 0;
const bit<32> CNTR_IDX_CPU      = 1;
const bit<32> CNTR_IDX_IP       = 2;

header ethernet_t {
    macAddr_t       dstAddr;
    macAddr_t       srcAddr;
    bit<16>         etherType;
}

header cpu_metadata_t {
    bit<8>          fromCpu;
    bit<16>         origEtherType;
    bit<16>         srcPort;
}

header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
    // assumes hardware type is ethernet and protocol is IP
    macAddr_t srcEth;
    ip4Addr_t srcIP;
    macAddr_t dstEth;
    ip4Addr_t dstIP;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct headers {
    ethernet_t        ethernet;
    cpu_metadata_t    cpu_metadata;
    arp_t             arp;
    ipv4_t            ipv4;
}

struct metadata { }

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select (hdr.ethernet.etherType) {
            TYPE_ARP:           parse_arp;
            TYPE_CPU_METADATA:  parse_cpu_metadata;
            TYPE_IPV4:          parse_ipv4;
            default:            accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEtherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4); 
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { 
        verify_checksum(
            hdr.ipv4.isValid(),
            {   // inputs listed as 16bit words 
                hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags, hdr.ipv4.fragOffset,
                hdr.ipv4.ttl, hdr.ipv4.protocol,
                // skp the old csum when computing the new
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr 
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    counter(3, CounterType.packets) packet_counter;

    ip4Addr_t next_hop_ip = 0;
    macAddr_t next_hop_mac = hdr.ethernet.dstAddr;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_egr(port_t port) {
        standard_metadata.egress_spec = port;
    }

    action set_mgid(mcastGrp_t mgid) {
        standard_metadata.mcast_grp = mgid;
    }

    action cpu_meta_encap() {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
        hdr.cpu_metadata.srcPort = (bit<16>)standard_metadata.ingress_port;
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
    }

    action cpu_meta_decap() {
        hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
        hdr.cpu_metadata.setInvalid();
    }

    // this will exit the ingress control block!!!!
    action send_to_cpu() {
        cpu_meta_encap();
        standard_metadata.egress_spec = CPU_PORT;
        packet_counter.count(CNTR_IDX_CPU);
        exit;
    }

    action find_next_hop_ip(ip4Addr_t dstAddr) {
        next_hop_ip = dstAddr;
    }

    action find_next_hop_mac(macAddr_t dstAddr) {
        next_hop_mac = dstAddr;
    }

    action decr_ttl() {
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    // table maps mac address to port
    table fwd_l2 {
        key = { hdr.ethernet.dstAddr: exact; } 
        actions = { set_egr; set_mgid; drop; NoAction; }
        size = 1024;
        default_action = drop();
    }

    table ipv4_routing {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { find_next_hop_ip; send_to_cpu; drop; NoAction; }
        size = 1024;
        default_action = NoAction;
    }

    table arp_table {
        key = { next_hop_ip: exact; }
        actions = { find_next_hop_mac; send_to_cpu; drop; NoAction; }
        size = 64;
        default_action = send_to_cpu();
    }

    table local_ip_table {
        key = { hdr.ipv4.dstAddr: exact; }
        actions = { send_to_cpu; drop; NoAction; }
        default_action = NoAction;
    }

    apply {
        // let cpu process non-IPV4
        if (!hdr.ipv4.isValid() && standard_metadata.ingress_port != CPU_PORT) {
            send_to_cpu();
        }

        // if received from cpu, unwrap it
        if (standard_metadata.ingress_port == CPU_PORT) {
            cpu_meta_decap();
        }

        if (hdr.ethernet.isValid()) {
            if (hdr.ipv4.isValid()) {
                
                packet_counter.count(CNTR_IDX_IP);

                // check if addressed to the router
                local_ip_table.apply();

                // calculate next hop information
                ipv4_routing.apply();
                arp_table.apply();

                // verify checksum
                if (standard_metadata.checksum_error == 1)
                    send_to_cpu(); 

                // verify and decrement ttl
                if (hdr.ipv4.ttl == 0)
                    send_to_cpu();

                decr_ttl();

                if (hdr.ipv4.ttl == 0)
                    send_to_cpu();

                // if you reached here, it's a valid ipv4 packet that wasn't sent to cpu
                hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
                hdr.ethernet.dstAddr = next_hop_mac;
            }

            if (hdr.arp.isValid())
                packet_counter.count(CNTR_IDX_ARP);

            // send ethernet packet to correct port
            fwd_l2.apply();
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply { 
        update_checksum(
            hdr.ipv4.isValid(),
            {   
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr 
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
