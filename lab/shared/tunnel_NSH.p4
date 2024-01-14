/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// taken from class lab
const bit<16> TYPE_MYTUNNEL = 0x1212;
const bit<16> TYPE_IPV4 = 0x0800;

// taken from NSH RFC 8300 https://www.rfc-editor.org/rfc/rfc8300.html
const bit<16> TYPE_NSH = 0x894F;
const bit<8> TYPE_IPV4_for_NSH = 0x01;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9> egressSpec_t; // Egress port specification

// Ethernet header
header ethernet_t {
    bit<48> dstAddr;    // Destination MAC address
    bit<48> srcAddr;    // Source MAC address
    bit<16> etherType;  // Ethernet frame type
}

// my Tunnel header -> total 32 bits
header myTunnel_t {
    bit<16> proto_id;   // myTunnel_t protocol identifier
    bit<16> dst_id;     // Destination identifier for the tunnel
}


// NSH header (NSH MD Type 2) -> total 64 bits
// zero or more Variable-Length Context Headers MAY be added

//      0                   1                   2                   3
//      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |Ver|O|U|    TTL    |   Length  |U|U|U|U|MD Type| Next Protocol |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |          Service Path Identifier (SPI)        | Service Index |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |                                                               |
//     ~              Variable-Length Context Headers  (opt.)          ~
//     |                                                               |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// I can develop the NSH header by my own.
// So I remove all the fields not usefull for me

// my NSH header -> total 40 bits (I have been able to eliminate some bits)
header myNSH_t{
    bit<8> proto_id;    // next protocol identifier
    bit<24> SPI;        // NSH Service Path Identifier
    bit<8> SI;          // NSH Service Index
}

// IPv4 header
header ipv4_t {
    bit<4> version;         // IP version
    bit<4> ihl;             // IP header length
    bit<8> diffserv;        // Differentiated Services
    bit<16> totalLen;       // Total length of the IP packet
    bit<16> identification; // Identification field
    bit<3> flags;           // Fragmentation flags
    bit<13> fragOffset;     // Fragment offset
    bit<8> ttl;             // Time to Live
    bit<8> protocol;        // next level protocol
    bit<16> hdrChecksum;    // Header checksum
    bit<32> srcAddr;        // Source IP address
    bit<32> dstAddr;        // Destination IP address
}

struct metadata {
    /* empty */
}

// Order headers for packet parsing
struct headers {
    ethernet_t ethernet; // Ethernet header instance
    myTunnel_t myTunnel; // Tunnel header instance
    myNSH_t myNSH;       // NSH header instance
    ipv4_t ipv4;         // IPv4 header instance
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    // start with parsing obtaining ethernet
    state start {
        transition parse_ethernet;
    }

    // extract ethernet header and parse (base on what there is inside)
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_MYTUNNEL: parse_myTunnel;
            TYPE_NSH: parse_myNSH;
            TYPE_IPV4: parse_ipv4;
            default : accept;
        }
    }

    // extract my_Tunnel header and parse (base on what there is inside)
    state parse_myTunnel {
        packet.extract(hdr.myTunnel);
        transition select(hdr.myTunnel.proto_id) {
            TYPE_NSH: parse_myNSH;
            TYPE_IPV4: parse_ipv4; 
            default : accept;
        }
    }

    // extracts the myNSH header and parse (base on what there is inside)
    state parse_myNSH{
        packet.extract(hdr.myNSH);
        transition select(hdr.myNSH.proto_id) {
            TYPE_IPV4_for_NSH: parse_ipv4;
            default : accept;
        }
    }

    // extract IPV4 header and accepts the packet
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
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


    // ---------- ACTION ----------

    // drop packet
    action drop() {
        mark_to_drop(standard_metadata);
    }

    // add a tunnel header to the packet with the specified destination ID
    action push_myTunnel_header(egressSpec_t port, bit<16> tunnel_id){

        hdr.myTunnel.setValid();

        hdr.myTunnel.dst_id = tunnel_id;
        hdr.myTunnel.proto_id = TYPE_NSH;
        hdr.ethernet.etherType = TYPE_MYTUNNEL;

        standard_metadata.egress_spec = port;
    }

    // remove the myTunnel header from the packet
    action remove_myTunnel_header() {
        hdr.ethernet.etherType = hdr.myTunnel.proto_id; // TYPE_NSH
        hdr.myTunnel.setInvalid();
    }

    // add an NSH header to the packet with specified SPI and SI values
    action push_myNSH_header(bit<24> spi, bit<8> service_index) {

        hdr.myNSH.setValid();

        hdr.ethernet.etherType = TYPE_NSH; // QUESTO MANCAVA
        hdr.myNSH.proto_id = TYPE_IPV4_for_NSH;
        hdr.myNSH.SPI = spi;
        hdr.myNSH.SI = service_index;
    }

    // remove the NSH header from the packet, forward packet, decrement ipv4 ttl
    action remove_myNSH_header(egressSpec_t port) {

        // here I have put the "if" not because it is neeed, but because in a more complex architecture the ethernet header should look the Next Protocol of the NSH header (that we are removing) to know which type of packet there is inside.
        // But the proto_id of the ethernet is 16 bit, while the proto_id of the NSH is 8 bit, and it gives me error a direct assignment like hdr.ethernet.etherType = hdr.myNSH.proto_id

        if (hdr.myNSH.proto_id == TYPE_IPV4_for_NSH){
            hdr.ethernet.etherType = TYPE_IPV4;
        }
        hdr.myNSH.setInvalid();

        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    // decrement the IPv4 TTL and set the egress port for IPv4 forwarding (h2 to h1 traffic)
    action ipv4_forward(bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    // Set the egress port for forwarding (when packet has tunnel header, s2 and s4)
    action myTunnel_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }
    
    // update the NSH Service Index, add tunnel encapsulation, forward
    action myNSH_forward(egressSpec_t port, bit<16> new_tunnel_id) {
        // hdr.myNSH.SPI remains 200
        hdr.myNSH.SI = hdr.myNSH.SI - 1;

        hdr.myTunnel.setValid();

        hdr.myTunnel.dst_id = new_tunnel_id;
        hdr.myTunnel.proto_id = TYPE_NSH;
        hdr.ethernet.etherType = TYPE_MYTUNNEL;

        standard_metadata.egress_spec = port;
    }


    // ---------- TABLE ----------

    // table used for IPv4 forwarding decisions
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    // table used to handle packet encapsulation with NSH headers
    table myNSH_header {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            push_myNSH_header;
            drop;
            NoAction;
        }
        size = 1024;
    	default_action = NoAction;
    }

    // table used to forward packet according to the tunnel id and remove myTunnelHeader
    table myTunnel_exact {
        key = {
            hdr.myTunnel.dst_id: exact;
        }
        actions = {
            myTunnel_forward;
            remove_myTunnel_header;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    // table used to forward packet according to the NSH header and remove NSHeader
    table myNSH_exact {
        key = {
            hdr.myNSH.SPI: exact;
            hdr.myNSH.SI: exact;
        }
        actions = {
            myNSH_forward;
            push_myTunnel_header;
            remove_myNSH_header;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }
    
    apply {
        ipv4_lpm.apply();

        // Process only non-SNH and non-tunneled IPv4 packets
        if (hdr.ipv4.isValid() && !hdr.myTunnel.isValid() && !hdr.myNSH.isValid()) {
            myNSH_header.apply();
        }

        // process the tunneled packets
        if (hdr.myTunnel.isValid()){
            myTunnel_exact.apply();
        }

        // process NSH-ed packets (not already tunneled)
        if (hdr.myNSH.isValid() && !hdr.myTunnel.isValid()){
            myNSH_exact.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

// computes the checksum for the IPv4 header
// field of the IPV4 header are described before
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

// emits the headers to the output packet, the order is important for the Encapsulation
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.myTunnel);
        packet.emit(hdr.myNSH);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//  how packets are processed within the switch
V1Switch(
    MyParser(), // Handles packet parsing
    MyVerifyChecksum(), // Validates checksums
    MyIngress(), // Handles ingress processing
    MyEgress(), // Handles egress processing
    MyComputeChecksum(), //Computes checksums
    MyDeparser() //Defines how to deparse packets
) main;

