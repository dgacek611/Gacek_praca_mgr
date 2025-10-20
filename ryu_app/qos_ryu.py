from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types

class SimpleLearning(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # per-switch MAC table: dpid -> { mac: port }
        self.mac_to_port = {}

    def add_flow(self, dp, priority, match, actions, idle=60, hard=0, cookie=0x1, buffer_id=None):
        ofp = dp.ofproto
        p = dp.ofproto_parser
        inst = [p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        kwargs = dict(datapath=dp, priority=priority, match=match,
                      instructions=inst, idle_timeout=idle, hard_timeout=hard, cookie=cookie)
        if buffer_id is not None and buffer_id != ofp.OFP_NO_BUFFER:
            kwargs["buffer_id"] = buffer_id
        dp.send_msg(p.OFPFlowMod(**kwargs))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        p = dp.ofproto_parser

        self.logger.info(f"Connected: dpid={dp.id}")

        # pełne pakiety do kontrolera
        dp.send_msg(p.OFPSetConfig(datapath=dp, miss_send_len=ofp.OFPCML_NO_BUFFER, flags=0))

        # ogranicz szum: drop LLDP i IPv6
        self.add_flow(dp, 100, p.OFPMatch(eth_type=0x88cc), [])   # LLDP
        self.add_flow(dp, 100, p.OFPMatch(eth_type=0x86dd), [])   # IPv6

        # table-miss -> controller
        self.add_flow(dp, 0, p.OFPMatch(), [p.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)], idle=0, hard=0, cookie=0)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        p = dp.ofproto_parser
        dpid = dp.id

        in_port = msg.match.get('in_port')
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        src = eth.src
        dst = eth.dst
        eth_type = eth.ethertype

        # inicjalizacja tablicy MAC
        self.mac_to_port.setdefault(dpid, {})
        # learning: zapamiętaj, skąd widzimy src
        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst)

        # jeśli nie znamy celu:
        if out_port is None:
            # FLOOD tylko dla ARP; nieznany unicast drop (żeby nie robić burzy)
            if eth_type == ether_types.ETH_TYPE_ARP:
                actions = [p.OFPActionOutput(ofp.OFPP_FLOOD)]
                dp.send_msg(p.OFPPacketOut(datapath=dp,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           in_port=in_port,
                                           actions=actions,
                                           data=msg.data))
            # else: drop (nic nie wysyłamy)
            return

        # znamy wyjście → nigdy nie wysyłaj na ten sam port co wejście
        if out_port == in_port:
            return

        actions = [p.OFPActionOutput(out_port)]

        # instaluj jedną regułę per dst (prościej i bez „samowyjścia”)
        match = p.OFPMatch(eth_dst=dst)
        self.add_flow(dp, priority=10, match=match, actions=actions, buffer_id=msg.buffer_id)

        # jeśli switch nie zbuforował pakietu – wyślij go
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            dp.send_msg(p.OFPPacketOut(datapath=dp,
                                       buffer_id=ofp.OFP_NO_BUFFER,
                                       in_port=in_port,
                                       actions=actions,
                                       data=msg.data))