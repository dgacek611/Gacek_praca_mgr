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
    Prosty kontroler Ryu:
    - Table 0: klasyfikacja QoS (DSCP -> queue lub meter), drop LLDP/IPv6, goto table 1
    - Table 1: nauka MAC (reaktywne unicast flow)
    - Flood: tylko na porty hostów i porty drzewa rozpinającego
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # --- QoS map ---
    def _qos_mode(self) -> str:
        """Zwraca tryb QoS z env: none | hfsc | htb | meter."""
        return os.environ.get("QOS_MODE", "none").lower()

    _DSCP_MAP: Dict[int, Dict[str, int]] = {
        46: {"queue": 2, "meter": 1},  # EF
        26: {"queue": 1, "meter": 2},  # AF31
         0: {"queue": 0, "meter": 3},  # BE
    }

    def _install_qos_rules(self, dp) -> None:
        """Instaluje reguły QoS w table 0 i przekierowuje do table 1."""
        mode = self._qos_mode()
        if mode not in ("hfsc", "htb", "meter"):
            return

        ofp = dp.ofproto
        p = dp.ofproto_parser

        for dscp, spec in self._DSCP_MAP.items():
            match = p.OFPMatch(eth_type=0x0800, ip_dscp=dscp)

            if mode in ("hfsc", "htb"):
                actions = [p.OFPActionSetQueue(spec["queue"])]
                inst = [
                    p.OFPInstructionActions(ofp.OFPIT_WRITE_ACTIONS, actions),
                    p.OFPInstructionGotoTable(1),
                ]
            else:  # meter
                inst = [
                    p.OFPInstructionMeter(spec["meter"]),
                    p.OFPInstructionGotoTable(1),
                ]

            mod = p.OFPFlowMod(
                datapath=dp,
                table_id=0,
                priority=20000,
                match=match,
                instructions=inst,
            )
            dp.send_msg(mod)

            # Poprawiony log: queue= dla hfsc/htb, meter= dla meter
            if mode in ("hfsc", "htb"):
                target = f"queue={spec['queue']}"
            else:
                target = f"meter={spec['meter']}"
            self.logger.info("[QoS/%s] dpid=%s DSCP=%d -> %s",
                             mode, hex(dp.id), dscp, target)

    # --- twardy drop LLDP i domyślny goto tbl1 w table 0 ---
    def _add_drop_lldp(self, dp) -> None:
        """Drop LLDP w table 0."""
        p = dp.ofproto_parser
        match = p.OFPMatch(eth_type=0x88cc)
        dp.send_msg(p.OFPFlowMod(
            datapath=dp, table_id=0, priority=30000,
            match=match, instructions=[]
        ))

    def _add_default_goto_tbl1(self, dp) -> None:
        """Domyślnie kierujemy do table 1."""
        p = dp.ofproto_parser
        inst = [p.OFPInstructionGotoTable(1)]
        dp.send_msg(p.OFPFlowMod(
            datapath=dp, table_id=0, priority=1,
            match=p.OFPMatch(), instructions=inst
        ))

    # --- pomocnicze ---
    def purge_table0(self, dp) -> None:
        """Kasuje wpisy z table 0."""
        ofp = dp.ofproto
        p = dp.ofproto_parser
        dp.send_msg(p.OFPFlowMod(
            datapath=dp, table_id=0, command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY
        ))

    def add_drop_ipv6(self, dp) -> None:
        """Drop ramek IPv6 w table 0."""
        p = dp.ofproto_parser
        match = p.OFPMatch(eth_type=0x86dd)
        dp.send_msg(p.OFPFlowMod(
            datapath=dp, table_id=0, priority=10000,
            match=match, instructions=[]
        ))

    def _add_table_miss(self, dp, table_id: int = 0) -> None:
        """Table-miss -> PacketIn do kontrolera."""
        ofp = dp.ofproto
        p = dp.ofproto_parser
        actions = [p.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(p.OFPFlowMod(
            datapath=dp, table_id=table_id, priority=0,
            match=p.OFPMatch(), instructions=inst
        ))

    def __init__(self, *args, **kwargs):
        super(QoSTreeController, self).__init__(*args, **kwargs)
        # dpid -> {mac: port}
        self.mac_to_port: Dict[int, Dict[str, int]] = {}
        # dpid -> set(port_no) (porty, gdzie widzimy hosty)
        self.host_ports: Dict[int, Set[int]] = {}
        # dpid -> {neighbor_dpid: (out_port_local, in_port_remote)}
        self.graph: Dict[int, Dict[int, Tuple[int, int]]] = {}
        # dpid -> set(local_uplink_ports) (drzewo rozpinające)
        self.sp_tree: Dict[int, Set[int]] = {}
        # dpid -> datapath
        self.datapaths: Dict[int, object] = {}

    # --- zarządzanie switchami/topo ---
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        """Śledzenie aktywnych datapathów."""
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == 'dead' and dp.id in self.datapaths:
            self.datapaths.pop(dp.id, None)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Inicjalizacja switcha: table 0 QoS, dropy, goto 1, table-missy."""
        dp = ev.msg.datapath
        ofp = dp.ofproto
        p = dp.ofproto_parser

        self.logger.info("[SWITCH] Connected: dpid=%s", hex(dp.id))
        self.datapaths[dp.id] = dp

        # start od zera
        self.purge_table0(dp)
        dp.send_msg(p.OFPSetConfig(
            datapath=dp,
            miss_send_len=ofp.OFPCML_NO_BUFFER,
            flags=0
        ))

        # QoS (table 0) -> goto table 1
        try:
            self._install_qos_rules(dp)
        except Exception as e:
            self.logger.error("QoS rules install error: %s", e)

        # drop IPv6 i LLDP w table 0
        self.add_drop_ipv6(dp)
        self._add_drop_lldp(dp)

        # domyślnie: goto 1
        self._add_default_goto_tbl1(dp)

        # table-miss w 0 i 1
        self._add_table_miss(dp, table_id=0)
        self._add_table_miss(dp, table_id=1)

    def recompute_spanning_tree(self) -> None:
        """Liczy drzewo rozpinające (porty lokalne jako inty)."""
        if not self.graph:
            self.sp_tree = {}
            return

        root = min(self.graph.keys())
        visited = {root}
        parent = {root: None}

        from collections import deque
        q = deque([root])

        while q:
            u = q.popleft()
            for v in sorted(self.graph.get(u, {}).keys()):
                if v not in visited:
                    visited.add(v)
                    parent[v] = u
                    q.append(v)

        allowed: Dict[int, Set[int]] = {}
        for v, u in parent.items():
            if u is None:
                continue
            # self.graph[u][v] = (u_out_port, v_in_port)
            up_tuple = self.graph[u][v]
            vp_tuple = self.graph[v][u]
            up = up_tuple[0]  # lokalny port na u
            vp = vp_tuple[0]  # lokalny port na v
            allowed.setdefault(u, set()).add(up)
            allowed.setdefault(v, set()).add(vp)

        self.sp_tree = allowed
        self.logger.info("[TREE] %s", {hex(k): sorted(list(v)) for k, v in self.sp_tree.items()})

    def in_spanning_tree(self, dpid: int, port_no: int) -> bool:
        """Sprawdza, czy port należy do drzewa rozpinającego."""
        return port_no in self.sp_tree.get(dpid, set())

    @set_ev_cls(topo_event.EventSwitchEnter)
    def _switch_enter(self, ev):
        dpid = ev.switch.dp.id
        self.logger.info("[SWITCH+] %s entered", hex(dpid))
        self.datapaths[dpid] = ev.switch.dp

    @set_ev_cls(topo_event.EventLinkAdd)
    def _link_add(self, ev):
        """Dodaje krawędź do grafu i przelicza drzewo."""
        link = ev.link
        u, v = link.src.dpid, link.dst.dpid
        up, vp = link.src.port_no, link.dst.port_no
        self.logger.info("[LINK+] %s:%s <-> %s:%s", hex(u), up, hex(v), vp)
        self.graph.setdefault(u, {})[v] = (up, vp)
        self.graph.setdefault(v, {})[u] = (vp, up)
        self.recompute_spanning_tree()

    @set_ev_cls(topo_event.EventLinkDelete)
    def _link_delete(self, ev):
        """Usuwa krawędź z grafu i przelicza drzewo."""
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

        self.recompute_spanning_tree()

    @set_ev_cls(topo_event.EventSwitchLeave)
    def _switch_leave(self, ev):
        """Czyści wpisy dla przełącznika, który opuścił topo."""
        dpid = ev.switch.dp.id
        self.logger.info("[SWITCH-] %s left", hex(dpid))

        self.datapaths.pop(dpid, None)
        self.mac_to_port.pop(dpid, None)
        self.host_ports.pop(dpid, None)

        if dpid in self.graph:
            self.graph.pop(dpid, None)
            for u in list(self.graph.keys()):
                self.graph[u].pop(dpid, None)
                if not self.graph[u]:
                    self.graph.pop(u, None)
            self.recompute_spanning_tree()

    # --- floodery host-only (dla ARP) ---
    def arp_host_flood_global(self, in_dp, in_port: int, data: bytes) -> None:
        """Rozgłasza ARP wyłącznie na porty hostów wszystkich switchy."""
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

    # --- główny handler ramek ---
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
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

        # LLDP odrzucone w table 0 – nic nie rób
        if eth_type == 0x88cc:
            return

        # Uczenie źródła + klasyfikacja portu hosta
        self.mac_to_port.setdefault(dpid, {})[src] = in_port
        is_link_port = any(
            u_p == in_port for _, (u_p, v_p) in self.graph.get(dpid, {}).items()
        )
        if not is_link_port:
            self.host_ports.setdefault(dpid, set()).add(in_port)

        # ARP: flood globalny tylko na porty hostów
        if eth_type == 0x0806:  # ARP
            self.arp_host_flood_global(dp, in_port, msg.data)
            return

        # IPv4/pozostałe L2: jeśli znamy dst na tym dp, instalujemy unicast flow w TBL1
        if dst in self.mac_to_port.get(dpid, {}):
            out_port = self.mac_to_port[dpid][dst]

            # Table 1: match dl_dst -> OUTPUT out_port
            match = p.OFPMatch(eth_dst=dst)
            actions = [p.OFPActionOutput(out_port)]
            inst = [p.OFPInstructionActions(ofp.OFPIT_WRITE_ACTIONS, actions)]

            mod = p.OFPFlowMod(
                datapath=dp,
                table_id=1,
                priority=100,
                idle_timeout=20,
                hard_timeout=0,
                match=match,
                instructions=inst,
            )
            dp.send_msg(mod)

            # Wyślij bieżący pakiet
            dp.send_msg(p.OFPPacketOut(
                datapath=dp,
                buffer_id=ofp.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=msg.data
            ))
            return

        # Nie znamy dst: ograniczony flood (host-porty lokalne + porty drzewa)
        actions = []

        # porty hostów na tym dp
        for port in sorted(self.host_ports.get(dpid, set())):
            if port != in_port:
                actions.append(p.OFPActionOutput(port))

        # porty „uplinkowe” z drzewa
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
