/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<10> switchID_t;
typedef bit<48> time_t;
typedef bit<9> port_num_t;

const bit<16> TYPE_IPV4  = 0x800;
const bit<16> TYPE_PROBE_TRANSIT = 0x812;
const bit<16> TYPE_PROBE_SINK = 0x813;
const port_num_t CPU_PORT = 8;

#define MAX_HOPS 4
#define MAX_PORTS 8

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header probe_t {
    bit<8> hop_cnt;
}

header srcRoute_t {
    bit<7>   port;
    bit<1>   bos;
}

header int_data_t {
    bit<1> bos;
    switchID_t switch_id;   // 凑8的倍数
    bit<9> ingress_port;
    bit<9> egress_port;
    bit<48> hop_latency;    // 在这一跳耽误的时间
    bit<19> deq_qdepth;
    bit<32> deq_timedelta;
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


// Packet-in header. Prepended to packets sent to the controller and used to
// carry the original ingress port where the packet was received.
@controller_header("packet_in")
header packet_in_header_t {
    bit<9> ingress_port;
    bit<7> _padding;
}

// Packet-out header. Prepended to packets received by the controller and used
// to tell the switch on which port this packet should be forwarded.
@controller_header("packet_out")
header packet_out_header_t {
    bit<9> egress_port;
    bit<7> _padding;
}

struct metadata {
    switchID_t switch_id;
}


struct headers {
    packet_out_header_t     packet_out;
    packet_in_header_t      packet_in;
    ethernet_t              ethernet;
    srcRoute_t[MAX_HOPS]    srcRoutes;
    probe_t                 probe;
    int_data_t[MAX_HOPS]    int_data;
    ipv4_t                  ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_PROBE_TRANSIT: parse_srcRoutes;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_srcRoutes {
        packet.extract(hdr.srcRoutes.next);
        transition select(hdr.srcRoutes.last.bos) {
            1: parse_probe;
            default: parse_srcRoutes;
        }
    }

    state parse_probe {
        packet.extract(hdr.probe);
        transition select(hdr.probe.hop_cnt) {
            0: accept;
            default: parse_int_data;
        }
    }

    state parse_int_data {
        packet.extract(hdr.int_data.next);
        transition select(hdr.int_data.last.bos) {
            1: accept;
            default: parse_int_data;
        }
    }


}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }


    action srcRoute_nhop() {
        standard_metadata.egress_spec = (bit<9>)hdr.srcRoutes[0].port;
        hdr.srcRoutes.pop_front(1);
    }

    action srcRoute_finish() {
        hdr.ethernet.etherType = TYPE_PROBE_SINK;
    }

    action set_egress_port(port_num_t port_num) {
        // Specifies the output port for this packet by setting the
        // corresponding metadata.
        standard_metadata.egress_spec = port_num;
    }

    action send_to_CPU(){
        standard_metadata.egress_spec = CPU_PORT;
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = standard_metadata.ingress_port;
    }



    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    table l2_exact_table {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            set_egress_port;
            send_to_CPU;
            drop;
            NoAction;
        }
        default_action = drop();
    }

    apply{

        if(hdr.packet_out.isValid()){
            standard_metadata.egress_spec = hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
            exit;
        }

        if(hdr.srcRoutes[0].isValid()){
            if (hdr.srcRoutes[0].bos == 1){
                srcRoute_finish();
            }
            srcRoute_nhop();
            hdr.probe.hop_cnt = hdr.probe.hop_cnt + 1;
            exit;
        }

        if(hdr.ipv4.isValid()){
            ipv4_lpm.apply();
            if(hdr.ipv4.ttl == 0){
                drop();
            }
        }
        
        l2_exact_table.apply();
        
    }

}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_swid(switchID_t swid){
        meta.switch_id = swid;
    }

    table swid {
        actions = {
            set_swid;
            NoAction;
        }
        default_action=NoAction;
    }

    apply{
        swid.apply();
        if (hdr.ethernet.etherType == TYPE_PROBE_TRANSIT || hdr.ethernet.etherType == TYPE_PROBE_SINK) {
            hdr.int_data.push_front(1);
            hdr.int_data[0].setValid();
            if (hdr.probe.hop_cnt == 1) {
                hdr.int_data[0].bos = 1;
            }
            else {
                hdr.int_data[0].bos = 0;
            }
            hdr.int_data[0].switch_id = meta.switch_id;
            hdr.int_data[0].ingress_port = standard_metadata.ingress_port;
            hdr.int_data[0].egress_port = standard_metadata.egress_port;
            hdr.int_data[0].hop_latency = standard_metadata.egress_global_timestamp - standard_metadata.ingress_global_timestamp;
            hdr.int_data[0].deq_qdepth = standard_metadata.deq_qdepth;
            hdr.int_data[0].deq_timedelta = standard_metadata.deq_timedelta;
        }
    }

}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   ***************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.srcRoutes);
        packet.emit(hdr.probe);
        packet.emit(hdr.int_data);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
