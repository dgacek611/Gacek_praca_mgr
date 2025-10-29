from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet
from ryu.topology import event as topo_event

import os
from typing import Dict, Set, Tuple


class QoSTreeController(app_manager.RyuApp):
    """
    Co robi ten kontroler:
    - Table 0: klasy po DSCP (albo set_queue dla HTB/HFSC, albo meter dla policingu)
               + drop LLDP/IPv6 + domyślne goto:1
    - Table 1: proste „MAC learning” (reaktywne unicasty)
    - Flood: tylko porty hostów + porty będące w drzewie rozpinającym (żeby nie zalać pętli)
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # --- USTAWIENIA QoS ---
    def _qos_mode(self) -> str:
        """Skąd bierzemy tryb: none | hfsc | htb | meter (ENV: QOS_MODE)."""
        return os.environ.get("QOS_MODE", "none").lower()

    # Mapowanie DSCP -> kolejka/metery; to jest wspólne dla A/B/C
    # EF=46, AF31=26, BE=0 (reszta IPv4 wpada do BE w praktyce)
    _DSCP_MAP: Dict[int, Dict[str, int]] = {
        46: {"queue": 2, "meter": 1},  # EF
        26: {"queue": 1, "meter": 2},  # AF31
         0: {"queue": 0, "meter": 3},  # BE
    }

    # ------------------------------------------------------------------
    # 1) REGUŁY W TABLE 0 (KLASYFIKACJA + PRZELOT DO TABLE 1)
    # ------------------------------------------------------------------
    def _install_qos_rules(self, dp) -> None:
        """
        Wrzuca reguły QoS do TBL0 na bazie DSCP.
        - HTB/HFSC: set_queue -> goto:1
        - Meter:    meter:N  -> goto:1
        Jeżeli QOS_MODE=none to nic nie dokładamy (czyli baseline).
        """
        mode = self._qos_mode()
        if mode not in ("hfsc", "htb", "meter"):
            return

        ofp = dp.ofproto
        p = dp.ofproto_parser

        for dscp, spec in self._DSCP_MAP.items():
            match = p.OFPMatch(eth_type=0x0800, ip_dscp=dscp)

            if mode in ("hfsc", "htb"):
                # shaping/prio: wybieramy kolejkę
                actions = [p.OFPActionSetQueue(spec["queue"])]
                inst = [
                    p.OFPInstructionActions(ofp.OFPIT_WRITE_ACTIONS, actions),
                    p.OFPInstructionGotoTable(1),
                ]
            else:
                # policing: twarde cięcie nadmiaru przez meter
                inst = [
                    p.OFPInstructionMeter(spec["meter"]),
                    p.OFPInstructionGotoTable(1),
                ]

            dp.send_msg(p.OFPFlowMod(
                datapath=dp,
                table_id=0,
                priority=20000,              # wyżej niż domyślne
                match=match,
                instructions=inst,
            ))

            info = f"queue={spec['queue']}" if mode in ("hfsc", "htb") else f"meter={spec['meter']}"
            self.logger.info("[QoS/%s] dpid=%s DSCP=%d -> %s",
                             mode, hex(dp.id), dscp, info)

    def _add_drop_lldp(self, dp) -> None:
        """Twardy drop LLDP w TBL0 (nie potrzebujemy go w danych)."""
        p = dp.ofproto_parser
        match = p.OFPMatch(eth_type=0x88cc)
        dp.send_msg(p.OFPFlowMod(
            datapath=dp, table_id=0, priority=30000,
            match=match, instructions=[]
        ))

    def _add_drop_ipv6(self, dp) -> None:
        """Twardy drop ramek IPv6 w TBL0 (w labie wszystko IPv4)."""
        p = dp.ofproto_parser
        match = p.OFPMatch(eth_type=0x86dd)
        dp.send_msg(p.OFPFlowMod(
            datapath=dp, table_id=0, priority=10000,
            match=match, instructions=[]
        ))

    def _add_default_goto_tbl1(self, dp) -> None:
        """Fallback: jeśli nic nie pasuje, to leć do Table 1."""
        p = dp.ofproto_parser
        inst = [p.OFPInstructionGotoTable(1)]
        dp.send_msg(p.OFPFlowMod(
            datapath=dp, table_id=0, priority=1,
            match=p.OFPMatch(), instructions=inst
        ))

    def _add_table_miss(self, dp, table_id: int = 0) -> None:
        """Table-miss: dawaj pakiet do kontrolera (PacketIn)."""
        ofp = dp.ofproto
        p = dp.ofproto_parser
        actions = [p.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [p.OFPInstructionActions(ofp.OFPIT_WRITE_ACTIONS, actions)]
        dp.send_msg(p.OFPFlowMod(
            datapath=dp, table_id=table_id, priority=0,
            match=p.OFPMatch(), instructions=inst
        ))

    def _purge_table0(self, dp) -> None:
        """Czyszczenie TBL0 (po to, żeby start był deterministyczny)."""
        ofp = dp.ofproto
        p = dp.ofproto_parser
        dp.send_msg(p.OFPFlowMod(
            datapath=dp, table_id=0, command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY
        ))

    # ------------------------------------------------------------------
    # 2) ZDARZENIA — START/TOPO
    # ------------------------------------------------------------------
    def __init__(self, *args, **kwargs):
        super(QoSTreeController, self).__init__(*args, **kwargs)
        self.mac_to_port: Dict[int, Dict[str, int]] = {}          # dpid -> {mac -> port}
        self.host_ports: Dict[int, Set[int]] = {}                 # dpid -> {porty, gdzie są hosty}
        self.graph: Dict[int, Dict[int, Tuple[int, int]]] = {}    # (u -> v) -> (u_out, v_in)
        self.sp_tree: Dict[int, Set[int]] = {}                    # dpid -> porty „uplink” z drzewa
        self.datapaths: Dict[int, object] = {}

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change(self, ev):
        """Trzymamy listę aktywnych datapathów (przydaje się do floodu)."""
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == 'dead' and dp.id in self.datapaths:
            self.datapaths.pop(dp.id, None)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        """Pierwszy handshake — tu ustawiamy TBL0 i podstawy."""
        dp = ev.msg.datapath

        self.logger.info("[SWITCH] Connected: dpid=%s", hex(dp.id))
        self.datapaths[dp.id] = dp

        # zaczynamy od pustej TBL0
        self._purge_table0(dp)

        # instalujemy reguły QoS zależnie od trybu
        try:
            self._install_qos_rules(dp)
        except Exception as e:
            self.logger.error("QoS rules install error: %s", e)

        # twarde dropy i fallback
        self._add_drop_ipv6(dp)
        self._add_drop_lldp(dp)
        self._add_default_goto_tbl1(dp)

        # table-missy w 0 i 1 (inaczej sterownik by „nie widział” nieznanych)
        self._add_table_miss(dp, table_id=0)
        self._add_table_miss(dp, table_id=1)

    # --- topo: drzewo, żeby flood nie robił burzy ---
    @set_ev_cls(topo_event.EventSwitchEnter)
    def _sw_enter(self, ev):
        dpid = ev.switch.dp.id
        self.logger.info("[SWITCH+] %s entered", hex(dpid))
        self.datapaths[dpid] = ev.switch.dp

    @set_ev_cls(topo_event.EventSwitchLeave)
    def _sw_leave(self, ev):
        dpid = ev.switch.dp.id
        self.logger.info("[SWITCH-] %s left", hex(dpid))

        self.datapaths.pop(dpid, None)
        self.mac_to_port.pop(dpid, None)
        self.host_ports.pop(dpid, None)

        if dpid in self.graph:
            # wyrzucamy krawędzie z/do dpid
            self.graph.pop(dpid, None)
            for u in list(self.graph.keys()):
                self.graph[u].pop(dpid, None)
                if not self.graph[u]:
                    self.graph.pop(u, None)
            self._recompute_spanning_tree()

    @set_ev_cls(topo_event.EventLinkAdd)
    def _link_add(self, ev):
        """Kto z kim i na jakich portach — z tego układamy drzewo."""
        link = ev.link
        u, v = link.src.dpid, link.dst.dpid
        up, vp = link.src.port_no, link.dst.port_no
        self.logger.info("[LINK+] %s:%s <-> %s:%s", hex(u), up, hex(v), vp)
        self.graph.setdefault(u, {})[v] = (up, vp)
        self.graph.setdefault(v, {})[u] = (vp, up)
        self._recompute_spanning_tree()

    @set_ev_cls(topo_event.EventLinkDelete)
    def _link_del(self, ev):
        link = ev.link
        u, v = link.src.dpid, link.dst.dpid
        self.logger.info("[LINK-] %s <-> %s", hex(u), hex(v))

        if u in self.graph and v in self.graph[u]:
            self.graph[u].pop(v, None)
            if not self.graph[u]:
                self.graph.pop(u, None)

        if v in self.graph and u in self.graph[v]:
            self.graph[v].pop(u, None)
            if not self.graph[v]:
                self.graph.pop(v, None)

        self._recompute_spanning_tree()

    # ------------------------------------------------------------------
    # 3) DRZEWO ROZPINAJĄCE (żeby flood był cywilizowany)
    # ------------------------------------------------------------------
    def _recompute_spanning_tree(self) -> None:
        """BFS od minimalnego dpid – proste drzewo „wystarczy na lab”."""
        if not self.graph:
            self.sp_tree = {}
            return

        root = min(self.graph.keys())
        from collections import deque
        q = deque([root])

        visited = {root}
        parent = {root: None}

        while q:
            u = q.popleft()
            for v in sorted(self.graph.get(u, {}).keys()):
                if v not in visited:
                    visited.add(v)
                    parent[v] = u
                    q.append(v)

        # z rodziców wnioskujemy, które porty są „uplinkami”
        allowed: Dict[int, Set[int]] = {}
        for v, u in parent.items():
            if u is None:
                continue
            # self.graph[u][v] = (u_out_port, v_in_port)
            up_tuple = self.graph[u][v]
            vp_tuple = self.graph[v][u]
            u_out = up_tuple[0]   # lokalny port na u
            v_out = vp_tuple[0]   # lokalny port na v
            allowed.setdefault(u, set()).add(u_out)
            allowed.setdefault(v, set()).add(v_out)

        self.sp_tree = allowed
        self.logger.info("[TREE] %s", {hex(k): sorted(list(v)) for k, v in self.sp_tree.items()})

    # ------------------------------------------------------------------
    # 4) GŁÓWNY HANDLER PAKIETÓW
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
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

        # LLDP już dropujemy w TBL0, więc tu tylko sanity
        if eth_type == 0x88cc:
            return

        # Uczenie źródła + zapis „które porty to hosty”
        self.mac_to_port.setdefault(dpid, {})[src] = in_port
        # Port linkowy? (jeśli nie, to prawdopodobnie host)
        is_link = any(u_p == in_port for _, (u_p, v_p) in self.graph.get(dpid, {}).items())
        if not is_link:
            self.host_ports.setdefault(dpid, set()).add(in_port)

        # ARP rozgłaszamy globalnie, ale tylko na porty hostów (i bez pętli)
        if eth_type == 0x0806:  # ARP
            self._arp_host_flood_global(dp, in_port, msg.data)
            return

        # Jeżeli już znamy out_port na tym dp, instalujemy unicast w TBL1
        if dst in self.mac_to_port.get(dpid, {}):
            out_port = self.mac_to_port[dpid][dst]

            match = p.OFPMatch(eth_dst=dst)
            actions = [p.OFPActionOutput(out_port)]
            inst = [p.OFPInstructionActions(ofp.OFPIT_WRITE_ACTIONS, actions)]

            dp.send_msg(p.OFPFlowMod(
                datapath=dp,
                table_id=1,
                priority=100,
                idle_timeout=20,  # jak host zniknie, reguła sama zgaśnie
                hard_timeout=0,
                match=match,
                instructions=inst,
            ))

            # ...i wypchnij bieżący pakiet
            dp.send_msg(p.OFPPacketOut(
                datapath=dp,
                buffer_id=ofp.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=msg.data
            ))
            return

        # W innym wypadku „grzeczny” flood:
        # - do hostów na tym dp (poza portem wejściowym)
        # - do portów tworzących drzewo (bez zawracania na in_port)
        actions = []
        for port in sorted(self.host_ports.get(dpid, set())):
            if port != in_port:
                actions.append(p.OFPActionOutput(port))

        for port in sorted(self.sp_tree.get(dpid, set())):
            if port != in_port:
                actions.append(p.OFPActionOutput(port))

        if actions:
            dp.send_msg(p.OFPPacketOut(
                datapath=dp,
                buffer_id=ofp.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=msg.data
            ))

    # ------------------------------------------------------------------
    # 5) POMOCNICZE: broadcast ARP „tylko do hostów”
    # ------------------------------------------------------------------
    def _arp_host_flood_global(self, in_dp, in_port: int, data: bytes) -> None:
        """ARP rozgłaszamy do portów hostów na wszystkich dp (bez pętli)."""
        ofp = in_dp.ofproto
        p = in_dp.ofproto_parser
        for dpid, dp in list(self.datapaths.items()):
            for port in sorted(self.host_ports.get(dpid, set())):
                if dpid == in_dp.id and port == in_port:
                    continue
                dp.send_msg(p.OFPPacketOut(
                    datapath=dp,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    in_port=ofp.OFPP_CONTROLLER,
                    actions=[p.OFPActionOutput(port)],
                    data=data
                ))
