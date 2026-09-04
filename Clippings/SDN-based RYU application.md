---
title: "SDN-based RYU application"
source: "https://www.muzixing.com/pages/2014/10/19/ji-yu-sdnde-ryuying-yong-arp_proxy.html"
author:
  - "[[muzi]]"
published:
created: 2026-09-04
description:
tags:
  - "clippings"
---
[Muzixing](https://www.muzixing.com/)

## SDN-based RYU application - ARP\_PROXY

### Foreword

In traditional networks, broadcast traffic exists, consuming a portion of network bandwidth. Furthermore, in loop-based topologies, broadcast data can cause network storms and paralyze the network if certain protocols are not running. The traditional solution is to run STP (Spanning Tree Protocol) to mitigate the storm risks posed by loops. However, with the advent of SDN, solving this problem seems to have become simpler. This article will introduce how to develop an ARP proxy module on the RYU controller to proxy ARP request responses and resolve the problem of loop topology storms.

### Algorithm Logic

The specific algorithm flowchart is as follows:

```
packet_in
    |
    |
  ARP learning
  MAC_to_Port learning
    |
    |
    |               No  
Multicast? -------------------------------------------->|
    |                                                   |
    | Yes                                               |
    |                                                   |
    |                                                   |
    |      No                                           |
   loop? ----->(dpid,eth_src,dst_ip)learning            |
    |                   |                               |
    |                   |                               |
    |                   |               No              |         No
    |Yes        dst_ip in arp_table? ------->dst in mac_to_port? ---->Flood
    |                   |                               |               |
    |                   |Yes                            |Yes            |
    |                   |                               |               |
   drop             ARP_REPLY                       flow_mod            |
    |                   |                               |               |
    |                   |                               |               |
    |<------------------|<------------------------------|<--------------|               
    |
    |
    end
```

### Solving the ring storm

Before replying to ARP requests, the network loop problem must be addressed. Our solution is to record the in\_port of the first data packet using (dpid, eth\_src, arp\_dst\_ip) as the key, and discard packets returning from the network. This ensures that a broadcast packet within the same switch can only have one entry point, thus preventing loops. In this application, it is assumed that the first data packet initiating communication in the network is an ARP packet.

```
sw[(datapath.id, eth_src, arp_dst_ip)] = in_port
```

**The code is as follows:**

```
if eth_dst == ETHERNET_MULTICAST and ARP in header_list:
    arp_dst_ip = header_list[ARP].dst_ip
    if (datapath.id, eth_src, arp_dst_ip) in self.sw:  # Break the loop
        if self.sw[(datapath.id, eth_src, arp_dst_ip)] != in_port:
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=[], data=None)
            datapath.send_msg(out)
            return True
    else:
        self.sw[(datapath.id, eth_src, arp_dst_ip)] = in_port
```

### ARP reply

After resolving the broadcast storm issue in the loop topology, we also need to leverage the SDN controller's ability to obtain global network information to proxy ARP request responses, thereby reducing the flood of ARP request data in the network. This logic is very simple, essentially the same as the Layer 2 learning principle: it learns the host's ARP records, then queries and responds to those records. The specific code implementation is as follows:

```
if ARP in header_list:
    hwtype = header_list[ARP].hwtype
    proto = header_list[ARP].proto
    hlen = header_list[ARP].hlen
    plen = header_list[ARP].plen
    opcode = header_list[ARP].opcode

    arp_src_ip = header_list[ARP].src_ip
    arp_dst_ip = header_list[ARP].dst_ip

    actions = []

    if opcode == arp.ARP_REQUEST:
        if arp_dst_ip in self.arp_table:  # arp reply
            actions.append(datapath.ofproto_parser.OFPActionOutput(
                in_port)
            )

            ARP_Reply = packet.Packet()
            ARP_Reply.add_protocol(ethernet.ethernet(
                ethertype=header_list[ETHERNET].ethertype,
                dst=eth_src,
                src=self.arp_table[arp_dst_ip]))
            ARP_Reply.add_protocol(arp.arp(
                opcode=arp.ARP_REPLY,
                src_mac=self.arp_table[arp_dst_ip],
                src_ip=arp_dst_ip,
                dst_mac=eth_src,
                dst_ip=arp_src_ip))

            ARP_Reply.serialize()

            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                in_port=datapath.ofproto.OFPP_CONTROLLER,
                actions=actions, data=ARP_Reply.data)
            datapath.send_msg(out)
            return True
return False
```

### Postscript

In ring topologies, STP (Standard Protocol Layer) is commonly used to resolve broadcast storms, while SDN (Software-Defined Networking) offers a more efficient solution. Furthermore, after storm resolution, ARP proxy applications can be implemented. However, this simple application doesn't adequately address ARP issues because ARP records have a limited lifespan. Outdated data can disrupt network operations. Therefore, further optimization involves setting the refresh time for ARP records, as well as the refresh time for sw{dpid, eth\_src, arp\_dst\_ip}, to ensure data validity.

Extending this approach, we can process other broadcast data, such as DHCP, using the same pattern. The proxying of more function data packets or signaling data packets can also be implemented following this workflow. The complete code implementation is provided at the end of the article.

```
# Author:muzixing
# Time:2014/10/19
#

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp

ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ARP = arp.arp.__name__

class ARP_PROXY_13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ARP_PROXY_13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_table = {}
        self.sw = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=5, hard_timeout=15,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        header_list = dict(
            (p.protocol_name, p)for p in pkt.protocols if type(p) != str)
        if ARP in header_list:
            self.arp_table[header_list[ARP].src_ip] = src  # ARP learning

        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            if self.arp_handler(header_list, datapath, in_port, msg.buffer_id):
                # 1:reply or drop;  0: flood
                print "ARP_PROXY_13"
                return None
            else:
                out_port = ofproto.OFPP_FLOOD
                print 'OFPP_FLOOD'

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def arp_handler(self, header_list, datapath, in_port, msg_buffer_id):
        header_list = header_list
        datapath = datapath
        in_port = in_port

        if ETHERNET in header_list:
            eth_dst = header_list[ETHERNET].dst
            eth_src = header_list[ETHERNET].src

        if eth_dst == ETHERNET_MULTICAST and ARP in header_list:
            arp_dst_ip = header_list[ARP].dst_ip
            if (datapath.id, eth_src, arp_dst_ip) in self.sw:  # Break the loop
                if self.sw[(datapath.id, eth_src, arp_dst_ip)] != in_port:
                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                        in_port=in_port,
                        actions=[], data=None)
                    datapath.send_msg(out)
                    return True
            else:
                self.sw[(datapath.id, eth_src, arp_dst_ip)] = in_port

        if ARP in header_list:
            hwtype = header_list[ARP].hwtype
            proto = header_list[ARP].proto
            hlen = header_list[ARP].hlen
            plen = header_list[ARP].plen
            opcode = header_list[ARP].opcode

            arp_src_ip = header_list[ARP].src_ip
            arp_dst_ip = header_list[ARP].dst_ip

            actions = []

            if opcode == arp.ARP_REQUEST:
                if arp_dst_ip in self.arp_table:  # arp reply
                    actions.append(datapath.ofproto_parser.OFPActionOutput(
                        in_port)
                    )

                    ARP_Reply = packet.Packet()
                    ARP_Reply.add_protocol(ethernet.ethernet(
                        ethertype=header_list[ETHERNET].ethertype,
                        dst=eth_src,
                        src=self.arp_table[arp_dst_ip]))
                    ARP_Reply.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=self.arp_table[arp_dst_ip],
                        src_ip=arp_dst_ip,
                        dst_mac=eth_src,
                        dst_ip=arp_src_ip))

                    ARP_Reply.serialize()

                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                        in_port=datapath.ofproto.OFPP_CONTROLLER,
                        actions=actions, data=ARP_Reply.data)
                    datapath.send_msg(out)
                    return True
        return False
```