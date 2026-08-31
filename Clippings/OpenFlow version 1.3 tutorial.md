---
title: "OpenFlow version 1.3 tutorial"
source: "https://web.archive.org/web/20200708101509/http://sdnhub.org/tutorials/openflow-1-3/"
author:
published:
created: 2026-08-31
description: "OpenFlow version 1.3 is the latest version of OpenFlow that has support from switch vendors. It is significantly different from OpenFlow version 1.0 (which was"
tags:
  - "clippings"
---
The Wayback Machine - https://web.archive.org/web/20200708101509/http://sdnhub.org:80/tutorials/openflow-1-3/

OpenFlow version 1.3 is the latest version of OpenFlow that has support from switch vendors. It is significantly different from OpenFlow version 1.0 (which was the previous version several vendors supported). Among others, the main features added since then are:

- **1.1**: Support for MPLS, Q-in-Q, VLANs, multipath, multiple tables, logical ports
- **1.2**: Support for extensible headers (in match, packet\_in, set\_field), IPv6
- **1.3**: Support for tunneling, per-flow traffic meters, Provider Backbone Bridging

In this tutorial you will learn more about OpenFlow version 1.3 under the covers.

## 1\. Setup

To get started, download and set up the [SDNHub VM](https://web.archive.org/web/20200708101509/http://sdnhub.org/tutorials/sdn-tutorial-vm/) in Virtualbox or VMware.

The VM has wireshark and OFDissector installed for OpenFlow version 1.3. The dissector is based on CPqD’s [release](https://web.archive.org/web/20200708101509/https://github.com/CPqD/ofdissector). This enables us to inspect the exact syntax of the OpenFlow messages.

## 2\. Quickstart

- Run Mininet on a terminal window using the following command. This starts a network emulation environment to emulate 1 switch with 3 hosts.
```js
sudo mn --topo single,3 --mac --controller remote --switch ovsk,protocols=OpenFlow13
```
- Note that the above command will only work in our patched mininet. For other mininet installations, you can run the following command to make a switch supports OF 1.3:
```js
ovs-vsctl set bridge s1 protocols=OpenFlow13
```
- The Wireshark 1.11.3 that is part of the VM can parse OpenFlow 1.0, 1.1., 1.2, 1.3 and 1.4 messages. To start wireshark and view OpenFlow messages:
```js
sudo wireshark &
```
- Next, start the RYU Controller. Assume that the main folder where ryu is installed is in /home/ubuntu/ryu, The below command starts the controller by initiating the OpenFlow Protocol Handler and Simple Switch 1.3 application.
```js
cd /home/ubuntu/ryu && ./bin/ryu-manager --verbose ryu/app/simple_switch_13.py
```
- Next, check if the hosts in the mininet topology can reach each other
```js
mininet> h1 ping h3
PING 10.0.0.3 (10.0.0.3) 56(84) bytes of data.
64 bytes from 10.0.0.3: icmp_req=1 ttl=64 time=2.76 ms
64 bytes from 10.0.0.3: icmp_req=2 ttl=64 time=0.052 ms
64 bytes from 10.0.0.3: icmp_req=3 ttl=64 time=0.051 ms
```
- You can now list the ongoing flows using the following command that is specific to OpenFlow 1.3:
```js
sudo ovs-ofctl dump-flows s1 -O OpenFlow13
```

## 3\. Understanding OpenFlow Messages

Assuming you built the learning switch application from the previous section, we now take a deep dive into understanding the set of OpenFlow messages exchanged between controller and switch, as shown in the following figure.

[![OF_MESSAGES](https://web.archive.org/web/20200708101509im_/http://sdnhub.org/wp-content/uploads/2014/02/400x185xOF_Msg_Exchanges-300x135.png.pagespeed.ic.cwIx6VL3kp.png)](https://web.archive.org/web/20200708101509/http://sdnhub.org/wp-content/uploads/2014/02/OF_Msg_Exchanges.png)

#### Connection Setup

The switch initiates a standard TCP (or TLS) connection to the controller. When an OpenFlow connection is established, each entity must send an OFPT\_HELLO message with the protocol version set to the highest OpenFlow protocol version supported by the sender. In the below figure, we can see that OpenFlow version 1.3 has been negotiated.

[![OF_Hello](https://web.archive.org/web/20200708101509im_/http://sdnhub.org/wp-content/uploads/2014/02/OF_Hello1.png)](https://web.archive.org/web/20200708101509/http://sdnhub.org/wp-content/uploads/2014/02/OF_Hello1.png)

#### Feature Request – Reply

After successfully establishing a session, the controller sends an OFPT\_FEATURES\_REQUEST message. This message only contains an OpenFlow header and does not contain a body.

[![OF_Feature_Request](https://web.archive.org/web/20200708101509im_/http://sdnhub.org/wp-content/uploads/2014/02/OF_Feature_Request.png)](https://web.archive.org/web/20200708101509/http://sdnhub.org/wp-content/uploads/2014/02/OF_Feature_Request.png)

The switch responds with an OFPT\_FEATURES\_REPLY message. Notice the Datapath ID and the switch capabilities sent as part of the Feature reply message.

[![OF_Feature_Reply](https://web.archive.org/web/20200708101509im_/http://sdnhub.org/wp-content/uploads/2014/02/OF_Feature_Reply.png)](https://web.archive.org/web/20200708101509/http://sdnhub.org/wp-content/uploads/2014/02/OF_Feature_Reply.png)

#### Set Configuration

Next, the controller sends the OFPT\_SET\_CONFIG message to the switch. This includes the set of flags and Max bytes of packet that datapath should send to the controller.

[![OF_Set_Config](https://web.archive.org/web/20200708101509im_/http://sdnhub.org/wp-content/uploads/2014/02/OF_Set_Config.png)](https://web.archive.org/web/20200708101509/http://sdnhub.org/wp-content/uploads/2014/02/OF_Set_Config.png)

#### Multipart Request – Reply

The controller may request state from the datapath using the OFPT\_MULTIPART\_REQUEST message. The message types handled by this message include various statistics (FLOW/TABLE/PORT/QUEUE/METER etc) or description features (METER\_CONFIG/TABLE\_FEATURES/PORT\_DESC etc). In our simple\_switch\_13.py, RYU internally sends a MULTIPART\_REQUEST to request port description.

[![OF_Multipart_Request](https://web.archive.org/web/20200708101509im_/http://sdnhub.org/wp-content/uploads/2014/02/OF_Multipart_Request.png)](https://web.archive.org/web/20200708101509/http://sdnhub.org/wp-content/uploads/2014/02/OF_Multipart_Request.png)

The switch replies with the PORT\_DESCRIPTION of all active ports in the switch. Note: in OF 1.0, the port descriptions was returned as part of the FEATURE\_REPLY message. Now this is handled separately as MULTIPART\_\* in OF 1.3.

[![OF_Multipart_Reply](https://web.archive.org/web/20200708101509im_/http://sdnhub.org/wp-content/uploads/2014/02/OF_Multipart_Reply.png)](https://web.archive.org/web/20200708101509/http://sdnhub.org/wp-content/uploads/2014/02/OF_Multipart_Reply.png)

#### Flow Mod

Flows can be proactively (e.g., pre-install flows like **TableMissFlow**) or reactively (e.g., react for packet\_in messages) sent from the controller. Flow table modication messages can have the following types: OFPFC\_ADD, OFPFC\_DELETE, OFPFC\_DELETE\_STRICT, OFPFC\_MODIFY, OFPFC\_MODIFY\_STRICT.

In the following case, the controller installs a new flow, which shows that apart from the set of OF 1.0 parameters like priority, idle\_timeout etc, the match and instruction structure reflect the new parameters specified in 1.3.

[![OF_Flow_Mod](https://web.archive.org/web/20200708101509im_/http://sdnhub.org/wp-content/uploads/2014/02/OF_Flow_Mod.png)](https://web.archive.org/web/20200708101509/http://sdnhub.org/wp-content/uploads/2014/02/OF_Flow_Mod.png)  
It is important to note that the switch does not positively acknowledge for FLOW\_MOD messages. However, any error in the FLOW\_MOD request will be replied with OFPET\_FLOW\_MOD\_FAILED.

#### Set Async Configuration Message

Asynchronous messages are sent from a switch to the controller. The set of messages supported by the OpenFlow protocol include “Packet-Ins, Flow-Removed, Port-Status or Error” messages. When the switch connects to the controller, the controller can set the type of messages that it wants to receive on its OpenFlow channel.

[![OF_SetAsync](https://web.archive.org/web/20200708101509im_/http://sdnhub.org/wp-content/uploads/2014/03/300x229xOF_SetAsync.png.pagespeed.ic.847HA_IUly.jpg)](https://web.archive.org/web/20200708101509/http://sdnhub.org/wp-content/uploads/2014/03/OF_SetAsync.png)

Above picture shows an async config message sent by the controller. Depending on the type of flags set, various async messages can be received from the switch.

### Contributor:

Sriram Natarajan, RYU Code Contributor  
Any questions, email: natarajan(dot)sriram(at)gmail(dot)com