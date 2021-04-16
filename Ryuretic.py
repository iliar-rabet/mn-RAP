import logging
import struct
# Ryuretic framework files
from Pkt_Parse13 import Pkt_Parse
from switch_mod13 import SimpleSwitch
# Standard RYU calls
from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3 as ofproto #added
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet,ipv4,arp,icmp,tcp,udp

class coupler(app_manager.RyuApp):
    ''' This is the key to ryuretic: users should subclass the coupler
    in order to write their own programs. Look at the functions below:
    their definitions describe what should be done with each of the
    functions, and will note whether or not that function is optional
    to override. '''
    OFP_VERSIONS = [ofproto.OFP_VERSION] #ofproto_v1_3.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(coupler, self).__init__(*args, **kwargs)
        
        #modules are added to the coupler as objects
        self.switch=SimpleSwitch()


    #This decorator calls initial_event for packet arrivals
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def initial_event(self,ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        #Call <Pkt_Parse> to Build pkt object
        parsPkt = Pkt_Parse()
        pkt = parsPkt.handle_pkt(ev)

        #potential flag check for DP and inport. If flagged, bypass checks.
        #if port_monitor[pkt['dp']][pkt['inport']]['flag'] != None:
        #   self.apply_flag(pkt) #now create method in interface
        #Nest the rest in an else statement

        # Call appropriate handler for arriving packets (add IPv6,DHCP,etc.)
        if pkt['udp'] != None:
            self.handle_udp(pkt)
        elif pkt['tcp'] != None:
            self.handle_tcp(pkt)




    #Initialize switch to send all packets to controller (lowest priority)
    # Adds a Table-miss flow entry (see page 8 of "Ryu: Using OpenFlow 1.3"
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):      
        print("Received Switch features")
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

    ########################################################################
    # Adds flow to the switch so future packets aren't sent to the cntrl 
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

    ##############################################################        
    #Imeplement mac-learning (switch_mod13.py) for ethernet packets.  
    def install_field_ops(self, pkt, fields, ops):
        #Build match from pkt and fields
        match = self.pkt_match(fields)
        #print "Match Fields are:   ", match
	#Build actions from pkt and ops
        out_port, actions = self.pkt_action(pkt,ops,fields)
        priority = ops['priority']
        msg = fields['msg']                          
        parser, ofproto = fields['dp'].ofproto_parser, fields['ofproto']
        #print "install_field_ops ops: ", ops
        # install temporary flow to avoid future packet_in. 
        # idle_t and hard_t must be set to something. 
        if ops['idle_t']: # or ops['hard_t']:
            if out_port != ofproto.OFPP_FLOOD:

                self.add_timeFlow(fields['dp'], ops, match, actions)

        # For ping and wget, data = None
        data = None
        try:
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
        except:
            pass
        
        out = parser.OFPPacketOut(datapath=fields['dp'],
                                  buffer_id=msg.buffer_id,
                                  in_port=fields['inport'],
                                  actions=actions, data=data)

        #print "line 255 out: ", out
        fields['dp'].send_msg(out)


    #############################################################
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
#here 326-339
        elif ops['op'] == 'mod':
            print('Modifying pkt')
            actions.append(parser.OFPActionSetField(eth_src=fields['srcmac']))
	  #  actions.append(parser.OFPActionSetField(ipv4_src=fields['srcip']))
	   # actions.append(parser.OFPActionSetField(eth_dst=fields['dstmac']))
	    #actions.append(parser.OFPActionSetField(ipv4_dst=fields['dstip']))

 #           if fields['srcport'] != None:
		#actions.append(parser.OFPActionSetField(tcp_src=fields['srcport']))
#	    if fields['dstport'] != None:
#		actions.append(parser.OFPActionSetField(tcp_dst=fields['dstport']))
#	    if ops['newport'] != None:
#		out_port = ops['newport']
#		actions.append(parser.OFPActionOutput(ops['newport']))
#	    else:
#		out_port = self.switch.handle_pkt(pkt)
#		actions.append(parser.OFPActionOutput(out_port))

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

    #Receive crafted packet and send it to the switch
    def _send_packet(self, datapath, port, pkt_out):
        if port == None: 
        	print("Port not defined")
        #This methods sends the crafted message to the switch
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #print pkt_out
        pkt_out.serialize()
        #self.logger.info("packet-out %s" % (pkt_out,))
        data = pkt_out.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    #Clean up and disconnect ports. Controller going down
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def handl_port_stat(self, ev):
        switch=SimpleSwitch()
        switch.port_status_handler(ev)
