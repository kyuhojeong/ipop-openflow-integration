# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""

import logging
import struct

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

import fcntl
import json
import random
import socket
import threading
import select
import struct
import time

 
def getHwAddr(ifname): 
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])

IPOPBR_MAC = getHwAddr('ipopbr')
REM_ADDR = ""


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.run_once = True
        self.datapath = None
       
        self.oi_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.oi_sock.bind(("::1", 30001))
        t = threading.Thread(target=self.run_server)
        t.daemon = True
        t.start()


    def run_server(self):
        while True:
            print "running udp server"
            socks, _, _ = select.select([self.oi_sock], [], [], 30)
            for sock in socks:
                data, addr = sock.recvfrom(2048)
                print data
                print addr
                msg = json.loads(data)
                #if msg["type"] == "tincan_notify":
                    #  TODO It would not work more than three nodes, because of this. I need some implementation
                    # to combine rem_addr and stream at the same time with the same API call.
                #    REM_ADDR = msg["rem_addr"] 
                if msg["type"] == "packet_notify":
                    # TODO Port number should be assigned dynamically 
                    self.packet_translate2(guest_addr=msg["dst_ipv4"], 
                      host_addr=msg["remote_host_ipv4"], bridge_mac=IPOPBR_MAC,
                      src_mac=msg["src_mac"], nw_proto=msg["nw_proto"], #transport_port=msg["transport_port"],
                      output_ovs_port=1, dst_port=msg["dst_port"], dst_mac=msg["dst_mac"], random_port=msg["random_port"])
 

    def ipv4_to_int(self, string):
        ip = string.split('.')
        assert len(ip) == 4
        i = 0
        for b in ip:
            b = int(b)
            i = (i << 8) | b
        return i

    def packet_translate2(self, guest_addr, host_addr, bridge_mac, src_mac, nw_proto, output_ovs_port, dst_port, dst_mac, random_port):
        print "packet_translate {0} {1} {2} {3} {4} {5} {6} {7} {8}".format(guest_addr, host_addr, bridge_mac, src_mac, nw_proto, output_ovs_port, dst_port, dst_mac, random_port)  
        #time.sleep(3)
        if self.datapath == None:
            return
        ofproto = self.datapath.ofproto
        #random_port = random.randint(49152, 65535)
        #match = self.datapath.ofproto_parser.OFPMatch(dl_type=0x0800, nw_dst=self.ipv4_to_int(guest_addr), nw_dst_mask=32, tp_dst=5001)
        #match = self.datapath.ofproto_parser.OFPMatch(dl_type=0x0800, dl_dst=haddr_to_bin(dst_mac), nw_dst=self.ipv4_to_int(guest_addr), nw_dst_mask=32)
        #match = self.datapath.ofproto_parser.OFPMatch(dl_type=0x0800, nw_dst=self.ipv4_to_int(guest_addr), nw_dst_mask=32, tp_dst=5001)
        match = self.datapath.ofproto_parser.OFPMatch(dl_type=0x0800, nw_dst=self.ipv4_to_int(guest_addr), nw_dst_mask=32, nw_proto=nw_proto, tp_dst=dst_port)
        actions = []
        actions.append(self.datapath.ofproto_parser.OFPActionSetNwDst(self.ipv4_to_int(host_addr)))
        actions.append(self.datapath.ofproto_parser.OFPActionSetDlDst(haddr_to_bin(bridge_mac)))
        actions.append(self.datapath.ofproto_parser.OFPActionSetTpDst(random_port))
        actions.append(self.datapath.ofproto_parser.OFPActionOutput(65534))
        mod = self.datapath.ofproto_parser.OFPFlowMod(
            datapath=self.datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY+1, 
            #priority=1, 
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        self.datapath.send_msg(mod)
        
        #match2 = self.datapath.ofproto_parser.OFPMatch(dl_type=0x0800, nw_src=self.ipv4_to_int(host_addr), nw_dst_mask=32, tp_src=transport_port)
        match2 = self.datapath.ofproto_parser.OFPMatch(dl_type=0x0800, nw_src=self.ipv4_to_int(host_addr), nw_dst_mask=32, nw_proto=nw_proto, tp_src=random_port)
        actions = [self.datapath.ofproto_parser.OFPActionSetNwSrc(self.ipv4_to_int(guest_addr))]
        actions.append(self.datapath.ofproto_parser.OFPActionSetDlSrc(haddr_to_bin(src_mac)))
        actions.append(self.datapath.ofproto_parser.OFPActionSetTpSrc(dst_port))
        actions.append(self.datapath.ofproto_parser.OFPActionOutput(output_ovs_port))
        #actions.append(self.datapath.ofproto_parser.OFPActionOutput(65534))
        mod2 = self.datapath.ofproto_parser.OFPFlowMod(
            datapath=self.datapath, match=match2, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY+1,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        self.datapath.send_msg(mod2)

    def packet_translate(self):
        ofproto = datapath.ofproto
        match = datapath.ofproto_parser.OFPMatch(dl_type=0x0800, nw_dst=self.ipv4_to_int("192.168.4.13"), nw_dst_mask=32)
        actions = []
        actions.append(datapath.ofproto_parser.OFPActionSetNwDst(self.ipv4_to_int("192.168.0.35")))
        actions.append(datapath.ofproto_parser.OFPActionSetDlDst(haddr_to_bin("7a:1e:c9:de:5f:49")))
        actions.append(datapath.ofproto_parser.OFPActionOutput(65534))
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            #priority=ofproto.OFP_DEFAULT_PRIORITY,
            priority=1,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)
        
        match2 = datapath.ofproto_parser.OFPMatch(dl_type=0x0800, nw_src=self.ipv4_to_int("192.168.0.35"), nw_dst_mask=32, tp_src=5001)
        actions = [datapath.ofproto_parser.OFPActionSetNwSrc(self.ipv4_to_int("192.168.4.13"))]
        actions.append(datapath.ofproto_parser.OFPActionOutput(1))
        mod2 = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match2, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod2)

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))



        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            #priority=ofproto.OFP_DEFAULT_PRIORITY,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        
        msg = ev.msg
        #print msg
        #if self.run_once:
        #    self.packet_translate(msg.datapath)
        #    self.run_once = False
        datapath = msg.datapath
        #print datapath
        self.datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)
        print self.mac_to_port

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
            #return

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
