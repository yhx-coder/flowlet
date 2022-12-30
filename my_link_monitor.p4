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
const bit<16> TYPE_MY_TUNNEL = 0X814;
const bit<16> TYPE_MY_SERVICE = 0X811;


#define MAX_HOPS 4
#define MAX_PORTS 8

// flowlet
#define FLOWLET_REGISTER_SIZE 8192
#define FLOWLET_ID_WIDTH 16
// wait for enhancement
#define FLOWLET_TIMEOUT 48w50000

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
    bit<32>   byte_cnt;
    time_t    last_time;
    time_t    cur_time;
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

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header myTunnel_t {
    bit<16> tunnelId;
    bit<16> tunnelGroup;
}

header bandwidth_request_t {
    bit<32> bandwidth_B;
}


struct flow_arg_t {
    bit<32> srcAddr;
    bit<32> dstAddr;
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> expect_bandwidth;
}

struct metadata {
    switchID_t switch_id;

    bit<48> flowlet_last_stamp;
    bit<48> flowlet_time_diff;

    bit<16> flowlet_register_index;
    bit<16> flowlet_id;
    bit<48> flowlet_timeout;

    bit<16> ecmp_hash;

    flow_arg_t flow_arg;
}


struct headers {
    ethernet_t              ethernet;
    srcRoute_t[MAX_HOPS]    srcRoutes;
    probe_t                 probe;
    int_data_t[MAX_HOPS]    int_data;
    myTunnel_t              myTunnel;
    bandwidth_request_t     bandwidth_request;
    ipv4_t                  ipv4;
    tcp_t                   tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_PROBE_TRANSIT: parse_srcRoutes;
            TYPE_MY_TUNNEL: parse_myTunnel;
            TYPE_MY_SERVICE: parse_bandwidth_request;
            default: accept;
        }
    }

    state parse_bandwidth_request {
        packet.extract(hdr.bandwidth_request);
        transition parse_ipv4;
    }

    state parse_myTunnel {
        packet.extract(hdr.myTunnel);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            6 : parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
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

    register<bit<FLOWLET_ID_WIDTH>>(FLOWLET_REGISTER_SIZE) flowlet_to_id;
    register<bit<48>>(FLOWLET_REGISTER_SIZE) flowlet_time_stamp;

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

    action read_flowlet_registers(){

        //compute register index
        hash(meta.flowlet_register_index, HashAlgorithm.crc16_custom,
            (bit<16>)0,
            { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort},
            (bit<16>)8192);

         //Read previous time stamp
        flowlet_time_stamp.read(meta.flowlet_last_stamp, (bit<32>)meta.flowlet_register_index);

        //Read previous flowlet id
        flowlet_to_id.read(meta.flowlet_id, (bit<32>)meta.flowlet_register_index);

        //Update timestamp
        flowlet_time_stamp.write((bit<32>)meta.flowlet_register_index, standard_metadata.ingress_global_timestamp);

    }
   
    action update_flowlet_id(){
        bit<32> random_t;
        random(random_t, (bit<32>)0, (bit<32>)65000);
        meta.flowlet_id = (bit<16>)random_t;
        flowlet_to_id.write((bit<32>)meta.flowlet_register_index, (bit<16>)meta.flowlet_id);
    }

    action send_digest(){
        meta.flow_arg.srcAddr = hdr.ipv4.srcAddr;
        meta.flow_arg.dstAddr = hdr.ipv4.dstAddr;
        meta.flow_arg.srcPort = hdr.tcp.srcPort;
        meta.flow_arg.dstPort = hdr.tcp.dstPort;
        meta.flow_arg.expect_bandwidth = hdr.bandwidth_request.bandwidth_B;
        digest<flow_arg_t>(1,meta.flow_arg);
        hdr.bandwidth_request.setInvalid();
        hdr.ethernet.etherType = TYPE_IPV4;
    }

    // total_path_num 其实是总权重和
    action add_tunnel_header(bit<16> total_path_num){
        hash(meta.ecmp_hash, 
            HashAlgorithm.crc16,
            (bit<16>)0,
            {   hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.ipv4.protocol,
                meta.flowlet_id
            },
            total_path_num);
        hdr.myTunnel.setValid();
        hdr.myTunnel.tunnelId = meta.ecmp_hash;
        hdr.myTunnel.tunnelGroup = meta.flowlet_register_index;
        hdr.ethernet.etherType = TYPE_MY_TUNNEL;
    }

    action tunnel_forward(macAddr_t dstAddr){
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
    }

    table check_compute_task {
        key = {
            hdr.tcp.dstPort: exact;
        }
        actions = {
            send_digest;
            NoAction;
        }
        default_action = NoAction;
    }

    table tunnel_src {
        key = {
            meta.flowlet_register_index: exact;
        }
        actions = {
            add_tunnel_header;
            NoAction;
        }
        default_action = NoAction;
    }

    table myTunnel_group_to_nhop {
        key = {
            hdr.myTunnel.tunnelGroup: exact;
            hdr.myTunnel.tunnelId: range;
        }
        actions = {
            tunnel_forward;
            drop;
        }
        default_action = drop();
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
            drop;
            NoAction;
        }
        default_action = drop();
    }

    apply{

        // source route forward
        if(hdr.srcRoutes[0].isValid()){
            if (hdr.srcRoutes[0].bos == 1){
                srcRoute_finish();
            }
            srcRoute_nhop();
            hdr.probe.hop_cnt = hdr.probe.hop_cnt + 1;
            exit;
        }

        // insert tunnel header
        if(hdr.ipv4.protocol == 6 && !hdr.myTunnel.isValid()){
            if(check_compute_task.apply().hit){
                @atomic {
                    read_flowlet_registers();
                    meta.flowlet_time_diff = standard_metadata.ingress_global_timestamp - meta.flowlet_last_stamp;

                    //check if inter-packet gap is > 50ms
                    if (meta.flowlet_time_diff > FLOWLET_TIMEOUT){
                        update_flowlet_id();
                    }
                }
                
                tunnel_src.apply();
            }
        }

        // ipv4 forward
        if(hdr.ethernet.etherType == TYPE_IPV4){
            ipv4_lpm.apply();
            if(hdr.ipv4.ttl == 0){
                drop();
            }
        }
        // flowlet tunnel forword
        if(hdr.ethernet.etherType == TYPE_MY_TUNNEL){
            myTunnel_group_to_nhop.apply();
        }

        // lay2 forward
        l2_exact_table.apply();
        
    }

 }

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    // count the number of bytes seen since the last probe
    register<bit<32>>(MAX_PORTS) byte_cnt_reg;
    // remember the time of the last probe
    register<time_t>(MAX_PORTS) last_time_reg;

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

    action remove_tunnel_header(){
        hdr.myTunnel.setInvalid();
        hdr.ethernet.etherType = TYPE_IPV4;
    }

    table tunnel_dst {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            remove_tunnel_header;
            NoAction;
        }
        default_action = NoAction;
    }

    apply{
        swid.apply();

        // remove tunnel header
        if(hdr.ethernet.etherType == TYPE_MY_TUNNEL){
            tunnel_dst.apply();
        }

        bit<32> byte_cnt;
        bit<32> new_byte_cnt;
        time_t last_time;
        time_t cur_time = standard_metadata.egress_global_timestamp;
        // increment byte cnt for this packet's port
        byte_cnt_reg.read(byte_cnt, (bit<32>)standard_metadata.egress_port);
        byte_cnt = byte_cnt + standard_metadata.packet_length;
        // reset the byte count when a probe packet passes through
        new_byte_cnt = (hdr.ethernet.etherType == TYPE_PROBE_TRANSIT || hdr.ethernet.etherType == TYPE_PROBE_SINK) ? 0 : byte_cnt;
        byte_cnt_reg.write((bit<32>)standard_metadata.egress_port, new_byte_cnt);

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
            hdr.int_data[0].byte_cnt = byte_cnt;
            // read / update the last_time_reg
            last_time_reg.read(last_time, (bit<32>)standard_metadata.egress_port);
            last_time_reg.write((bit<32>)standard_metadata.egress_port, cur_time);
            hdr.int_data[0].last_time = last_time;
            hdr.int_data[0].cur_time = cur_time;
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
        packet.emit(hdr.ethernet);
        packet.emit(hdr.srcRoutes);
        packet.emit(hdr.probe);
        packet.emit(hdr.int_data);
        packet.emit(hdr.myTunnel);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
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