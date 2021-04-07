from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet,ipv4,arp,icmp,tcp,udp
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import ether_types

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def handle_eth(self,pkt):
        raise NotImplementedError("handle_eth must be overridden by child.")

    def handle_arp(self,pkt):
        raise NotImplementedError("handle_arp must be overridden by child.")

    def handle_ip(self,pkt):
        raise NotImplementedError("handle_ip must be overridden by child.")

    def handle_icmp(self,pkt):
        raise NotImplementedError("handle_ip must be overridden by child.")

    def handle_tcp(self,pkt):
        raise NotImplementedError("handle_ip must be overridden by child.")

    def handle_udp(self,pkt):
        raise NotImplementedError("handle_ip must be overridden by child.")

    def handle_unk(self,pkt):
        raise NotImplementedError("handle_ip must be overridden by child.")



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def _bld_match_vals(self, fields):
        match_vals = {}     
        fields_keys = fields['keys']
        if 'inport' in fields_keys:
            match_vals['in_port'] = fields['inport']
        if 'ethtype' in fields_keys:
            match_vals['eth_type'] = fields['ethtype']
        if 'srcmac' in fields_keys:
            match_vals['eth_src'] = fields['srcmac']
        if 'dstmac' in fields_keys:
            match_vals['eth_dst'] = fields['dstmac']
        if 'srcip' in fields_keys:
            match_vals['ipv4_src']= fields['srcip']
        if 'dstip' in fields_keys:
            match_vals['ipv4_dst'] = fields['dstip']
        if 'proto' in fields_keys:
            match_vals['ip_proto'] = fields['proto']
        if 'srcport' in fields_keys:
            match_vals['tcp_src'] = fields['srcport']
        if 'dstport' in fields_keys:
            match_vals['tcp_dst'] = fields['dstport']
        if 'data' in fields_keys:
            match_vals['data'] = fields['data']
        return match_vals     

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    ########################################################################
    # Adds flow to the switch so future packets are not sent to the
    # controller (requires priority, idle_t, and hard_t)
    def add_timeFlow(self, dp, ops, match, actions):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
            
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=dp,
                            priority=ops['priority'],
                            idle_timeout=ops['idle_t'],
                            match=match, instructions=inst)

        dp.send_msg(mod)

    ############################################################    
    # Choose the field and ops having the highest priority and assert it.    
    def _build_FldOps(xfields,xops):
        priority = 0
        for x in len(xfields):
            if xfields[x]['priority'] > priority:
                fields,ops = xfields[x],xops[x]
        return fields,ops 


    #Use fields to build match. These are passed to the switch.
    def pkt_match(self, fields):
        def build_match(fields):
            match_vals = {}     
            #fields_keys = fields.keys()
            #print "FIELDS ARE: ", fields
            fields_keys = fields['keys']
            if 'inport' in fields_keys:
                match_vals['in_port'] = fields['inport']
            if 'ethtype' in fields_keys:
                match_vals['eth_type'] = fields['ethtype']
            if 'srcmac' in fields_keys:
                match_vals['eth_src'] = fields['srcmac']
            if 'dstmac' in fields_keys:
                match_vals['eth_dst'] = fields['dstmac']
            if 'srcip' in fields_keys:
                match_vals['ipv4_src']= fields['srcip']
            if 'dstip' in fields_keys:
                match_vals['ipv4_dst'] = fields['dstip']
            if 'proto' in fields_keys:
                match_vals['ip_proto'] = fields['proto']
            if 'srcport' in fields_keys:
                match_vals['tcp_src'] = fields['srcport']
            if 'dstport' in fields_keys:
                match_vals['tcp_dst'] = fields['dstport']
            if 'data' in fields_keys:
                match_vals['data'] = fields['data']
            #print match_vals
            return match_vals

        parser = fields['dp'].ofproto_parser
        #match_vals = {}
        match_vals = build_match(fields)
        #print match_vals
        match = parser.OFPMatch(**match_vals)        
        return match

    ###############################################################
    # Determine action to be taken on packet ops={'op':None, 'newport':None}
    # User can forward , drop, redirect, mirror, or craft packets. 
    def pkt_action(self,pkt,ops,fields):
        #print"********************\npacket action\n*****************"
        actions = []
        #print "line 305. Ops: ", ops
        parser = fields['dp'].ofproto_parser
        if ops['op'] == 'fwd':
            out_port = self.switch.handle_pkt(pkt)
            actions.append(parser.OFPActionOutput(out_port))
        elif ops['op'] == 'drop':
            out_port = fields['ofproto'].OFPPC_NO_RECV
            actions.append(parser.OFPActionOutput(out_port))


#############################################################################
        elif ops['op'] == 'redir':
            out_port = ops['newport']
            #print "line 312: dstmac: ", fields['dstmac']
            #print "line 313: dstip: ", fields['dstip']
            #print pkt['dstip']
            #This may no longer be necessary
            if pkt['ip'] is not None:
                actions.append(parser.OFPActionSetField(eth_dst=fields['dstmac']))
                actions.append(parser.OFPActionSetField(ipv4_dst=fields['dstip']))
            actions.append(parser.OFPActionOutput(out_port))
        elif ops['op'] == 'mir':
            out_port = self.switch.handle_pkt(pkt)
            actions.append(parser.OFPActionOutput(out_port))
            mir_port = ops['newport']
            actions.append(parser.OFPActionOutput(mir_port))
        elif ops['op'] == 'craft':
            #print "***\nCrafting Packet\n***"
            #create and send new pkt due to craft trigger
            self._build_pkt(fields, ops) 
            #Now drop the arrived packet
            out_port = fields['ofproto'].OFPPC_NO_RECV
            actions.append(parser.OFPActionOutput(out_port))
                                                
        return out_port, actions

    #More work is required here to implement active testing for NATs etc.
    # Note fields object must be completely rewritten for crafted packet
    # Probably need to make fields['ptype'] = ['arp', 'ipv4']
    def _build_pkt(self, fields, ops):
        pkt_out = packet.Packet()
        pkt_ipv4 = pkt_out.get_protocol(ipv4.ipv4)
        pkt_icmp = pkt_out.get_protocol(icmp.icmp)

        def addIPv4(pkt_out, fields):
            pkt_out.add_protocol(ipv4.ipv4(dst=fields['dstip'],
                                version = 4,
                                header_length = 5,
                                tos = 0,
                                total_length = 0,
                                identification = fields['id'],
                                flags=0x02,
                                ttl = 63,
                                proto = fields['proto'],
                                csum = 0,
                                option = None,
                                src=fields['srcip']))
            return pkt_out

        def addARP(pkt_out,fields):
            pkt_out.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                 src_mac=fields['srcmac'],
                                 src_ip=fields['srcip'],
                                 dst_mac=fields['dstmac'],
                                 dst_ip=fields['dstip']))
            return pkt_out

        pkt_out.add_protocol(ethernet.ethernet(ethertype=fields['ethtype'],
                                               dst=fields['dstmac'],
                                               src=fields['srcmac']))
        # Add if ARP                                           
        if 'arp' in fields['ptype']:
            pkt_out.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                 src_mac=fields['srcmac'],
                                 src_ip=fields['srcip'],
                                 dst_mac=fields['dstmac'],
                                 dst_ip=fields['dstip']))
        # Add if IPv4
        if 'ipv4' in fields['ptype']:
            pkt_out = addIPv4(pkt_out,fields)

        # Add if ICMP
        if 'icmp' in fields['ptype']:
            pkt_out = addIPv4(pkt_out,fields)
            
            pkt_out.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                 code=icmp.ICMP_ECHO_REPLY_CODE,
                                 csum=0,
                                 data=None))
        # Add if UDP    
        if 'udp' in fields['ptype']:
            #pkt_out = addARP(pkt_out,fields)
            pkt_out = addIPv4(pkt_out,fields)
            pkt_out.add_protocol(udp.udp(dst_port=fields['dstport'],
                                csum = 0,
                                total_length = 0,
                                src_port=fields['srcport']))

        # Add if TCP                         	 
        if 'tcp' in fields['ptype']:
            pkt_out = addIPv4(pkt_out,fields)
            pkt_out.add_protocol(tcp.tcp(dst_port=fields['dstport'],
				bits=fields['bits'],option=fields['opt'],
                                src_port=fields['srcport']))
            
        #Add covert channel information                    
        if fields['com'] != None:
            pkt_out.add_protocol(fields['com'])
            
        #Send crafted packet
        #print "Packet out: \n"
        #print pkt_out
        self._send_packet(fields['dp'], ops['newport'], pkt_out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        print('yes')
        datapath.send_msg(out)


   
