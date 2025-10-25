from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.topology import event as topo_event

class QoSTreeController(app_manager.RyuApp):
    def arp_host_flood_global(self, in_dp, in_port, data):
        """Controller-mediated ARP flood only to known host-facing ports on *all* switches.
        Safe: never touches inter-switch links, so no pętli.
        """
        ofp = in_dp.ofproto
        p = in_dp.ofproto_parser
        for dpid, dp in list(self.datapaths.items()):
            for port in sorted(self.host_ports.get(dpid, set())):
                if dpid == in_dp.id and port == in_port:
                    continue
                dp.send_msg(p.OFPPacketOut(datapath=dp,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           in_port=ofp.OFPP_CONTROLLER,
                                           actions=[p.OFPActionOutput(port)],
                                           data=data))

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    REQUIREMENTS = ['ryu.topology.switches'] # włącz LLDP/topology discovery

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.graph = {}       # graf sąsiedztwa (dpid -> {nbr: (mój_port, ich_port)})
        self.tree_ports = {}  # porty należące do drzewa
        self.host_ports = {}  # porty do hostów (nie między-switchowe)
        self.datapaths = {}   # aktywne datapathy (switches)

    # ---------------- Helpers ----------------
    def add_flow(self, dp, priority, match, actions, idle=60, hard=0, cookie=0x1, buffer_id=None):
        ofp = dp.ofproto
        p = dp.ofproto_parser
        inst = [p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        kwargs = dict(datapath=dp, priority=priority, match=match,
                      instructions=inst, idle_timeout=idle, hard_timeout=hard, cookie=cookie)
        if buffer_id is not None and buffer_id != ofp.OFP_NO_BUFFER:
            kwargs["buffer_id"] = buffer_id
        dp.send_msg(p.OFPFlowMod(**kwargs))

    def purge_table0(self, dp):
        ofp = dp.ofproto
        p = dp.ofproto_parser
        # Delete ALL flows in table 0
        fm = p.OFPFlowMod(datapath=dp,
                          command=ofp.OFPFC_DELETE,
                          out_port=ofp.OFPP_ANY,
                          out_group=ofp.OFPG_ANY,
                          table_id=0,
                          match=p.OFPMatch())
        dp.send_msg(fm)

    def recompute_spanning_tree(self):
        if not self.graph:
            self.tree_ports = {}
            return
        root = min(self.graph.keys()) # prosty wybór korzenia
        # DFS po grafie; zbieramy krawędzie drzewa
        # z krawędzi wyciągamy numery portów -> self.tree_ports[dpid] = {porty}
        visited = {root}
        stack = [root]
        tree_edges = set()
        while stack:
            u = stack.pop()
            for v, (u_p, v_p) in self.graph[u].items():
                if v in visited:
                    continue
                visited.add(v); stack.append(v)
                tree_edges.add((u, v)); tree_edges.add((v, u))
        new_tree_ports = {dpid: set() for dpid in self.graph.keys()}
        for u, v in tree_edges:
            u_p, v_p = self.graph[u][v]
            new_tree_ports[u].add(u_p)
        self.tree_ports = new_tree_ports
        self.logger.info("[TREE] %s", {hex(k): sorted(list(v)) for k, v in self.tree_ports.items()})

    def tree_flood(self, dp, in_port, data):
        # przy całkowitym „zimnym starcie” jest wariant globalny: kontroler wysyła PacketOut do host-portów na wszystkich przełącznikach (dalej bez dotykania portów łączących switche)
        p = dp.ofproto_parser
        ofp = dp.ofproto
        dpid = dp.id
        allowed = set(self.tree_ports.get(dpid, set())) | set(self.host_ports.get(dpid, set()))
        if not allowed:
            self.logger.debug("[FLOOD] cold-start: no tree/host ports on %s", hex(dpid))
            return
        actions = [p.OFPActionOutput(port) for port in sorted(allowed) if port != in_port]
        if not actions:
            return
        dp.send_msg(p.OFPPacketOut(datapath=dp,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   in_port=in_port,
                                   actions=actions,
                                   data=data))

    # ---------------- OpenFlow ----------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        p = dp.ofproto_parser

        self.logger.info("[SWITCH] Connected: dpid=%s", hex(dp.id))
        self.datapaths[dp.id] = dp

        # --- podczas łączenia switcha ---

        self.purge_table0(dp) # usuń stare flowy

        # wysyła do przełącznika (datapatha) wiadomość OFPT_SET_CONFIG - gdy coś trafia do kontrolera, nie buforuj tego — wyślij mi pełny pakiet
        dp.send_msg(p.OFPSetConfig(datapath=dp, miss_send_len=ofp.OFPCML_NO_BUFFER, flags=0))

        # zrzucenie szumów IPv6.
        self.add_flow(dp, 100, p.OFPMatch(eth_type=0x86dd), [])

        # dodanie reguły miss-table (płaszczyzna danych odsyła nieznane do kontrolera)
        self.add_flow(dp, 0, p.OFPMatch(),
                      [p.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)],
                      idle=0, hard=0, cookie=0)

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
        if not eth:
            return
        src, dst, eth_type = eth.src, eth.dst, eth.ethertype
        # Ignoruj ramki LLDP
        if eth_type == 0x88cc:
            return
        
        # --- uczenie MAC + oznaczanie portów hostów ---

        # nauka źródła i oznaczenie portu hosta - jeżeli port nie jest portem „między-switchowym” -> to port hosta
        self.mac_to_port.setdefault(dpid, {})[src] = in_port
        is_link_port = any(u_p == in_port for _, (u_p, v_p) in self.graph.get(dpid, {}).items())
        if not is_link_port:
            self.host_ports.setdefault(dpid, set()).add(in_port)

        # --- instalacja reguły dla znanego unicastu (reaktywny SDN) ---

        # klasyczny „learning switch” w SDN — reguły są instalowane reaktywnie per-MAC-dst. 
        out_port = self.mac_to_port[dpid].get(dst)
        if out_port is not None and out_port != in_port:
            actions = [p.OFPActionOutput(out_port)]
            match = p.OFPMatch(eth_dst=dst)         # najprostszy match; tu można dodać np. ip_dscp, eth_type=0x0800, itp.
            self.add_flow(dp, 10, match, actions, buffer_id=msg.buffer_id)
            # jeśli switch nie buforował pakietu, doślij go PacketOut
            if msg.buffer_id == ofp.OFP_NO_BUFFER:
                dp.send_msg(p.OFPPacketOut(datapath=dp,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           in_port=in_port,
                                           actions=actions,
                                           data=msg.data))
            return

        # --- bezpieczny flood ARP (bez OFPP_FLOOD) ---

        # nieznane → tylko ARP flood; reszta drop
        if eth_type == ether_types.ETH_TYPE_ARP:
            if not (self.tree_ports.get(dpid) or self.host_ports.get(dpid)):
                # w absolutnym cold-starcie: rozgłoś ARP tylko na znane porty hostów
                # na wszystkich switchach (nigdy po łączach między-switchowych)   
                self.arp_host_flood_global(dp, in_port, msg.data) # tylko host-porty na wszystkich switchach
            else:
                # Preferuj flood po portach drzewa + portach hostów na DANYM switchu
                self.tree_flood(dp, in_port, msg.data) # flood po drzewie + host-porty
            # Inne nieznane: brak PacketOut => efektywnie drop

    # ---------------- Topology ----------------
    @set_ev_cls(topo_event.EventLinkAdd)
    def _link_add_handler(self, ev):
        s = ev.link.src; d = ev.link.dst
        self.graph.setdefault(s.dpid, {})[d.dpid] = (s.port_no, d.port_no)
        self.graph.setdefault(d.dpid, {})[s.dpid] = (d.port_no, s.port_no)
        self.logger.info("[LINK+] %s:%d <-> %s:%d",
                         hex(s.dpid), s.port_no, hex(d.dpid), d.port_no)
        # --- liczenie drzewa rozpinającego ---
        # proste DFS od minimalnego dpid; z krawędzi drzewa zbieramy numery portów,
        # które zapisujemy w self.tree_ports[dpid] i później używamy ich do floodowania.
        self.recompute_spanning_tree()

    @set_ev_cls(topo_event.EventLinkDelete)
    def _link_del_handler(self, ev):
        s = ev.link.src; d = ev.link.dst; changed = False
        if s.dpid in self.graph and d.dpid in self.graph[s.dpid]:
            del self.graph[s.dpid][d.dpid]; changed = True
            if not self.graph[s.dpid]: self.graph.pop(s.dpid, None)
        if d.dpid in self.graph and s.dpid in self.graph[d.dpid]:
            del self.graph[d.dpid][s.dpid]; changed = True
            if not self.graph[d.dpid]: self.graph.pop(d.dpid, None)
        self.logger.info("[LINK-] %s <-> %s", hex(s.dpid), hex(d.dpid))
        if changed: self.recompute_spanning_tree()

    @set_ev_cls(topo_event.EventSwitchEnter)
    def _switch_enter(self, ev):
        self.logger.info("[SWITCH+] %s entered", hex(ev.switch.dp.id))

    @set_ev_cls(topo_event.EventSwitchLeave)
    def _switch_leave(self, ev):
        # usuwa datapath z rejestru i czyści wpisy MAC/host-porty/graf, a potem przelicza drzewo jeszcze raz
        dpid = ev.switch.dp.id
        self.logger.info("[SWITCH-] %s left", hex(dpid))
        self.datapaths.pop(dpid, None)
        self.mac_to_port.pop(dpid, None)
        self.host_ports.pop(dpid, None)
        if dpid in self.graph:
            self.graph.pop(dpid, None)
            for u in list(self.graph.keys()):
                self.graph[u].pop(dpid, None)
                if not self.graph[u]: self.graph.pop(u, None)
            self.recompute_spanning_tree()
