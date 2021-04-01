from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0

class L2Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
   # The trick is the 'set_ev_cls' decorator. This decorator tells Ryu
   # when the decorated function should be called.The first argument of
   # the decorator indicates which type of event this function should be
   # called for. As you might expect, every time Ryu gets a
   # packet_in message, this function is called.The second argument
   # indicates the state of the switch. You probably want to ignore
   # packet_in messages before the negotiation between Ryu and the switch
   # is finished. Using 'MAIN_DISPATCHER' as the second argument means
   # this function is called only after the negotiation completes.


#This is called when a ryu receives an OpenFlow packet_in message

    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
             data = msg.data

        out = ofp_parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data = data)
        dp.send_msg(out)

        print("hi")
