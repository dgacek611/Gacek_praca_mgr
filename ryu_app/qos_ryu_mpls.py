import os
from typing import Dict, Set, Tuple, Optional

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet
from ryu.lib.packet import ether_types
from ryu.topology import event as topo_event


# ========= Helpers: ENV parsing =========

def _env_flag(name: str, default: str = "") -> str:
    """Return trimmed environment variable value (or default)."""
    return os.environ.get(name, default).strip()


def _parse_dpid_list(env_val: str) -> Set[int]:
    """
    Parse comma-separated list of DPID values in decimal or hex (e.g. "2, 0x3").
    Returns a set of ints. Ignores invalid tokens.
    """
    s = env_val.strip()
    if not s:
        return set()

    out: Set[int] = set()
    for tok in s.split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            out.add(int(tok, 0))  # accepts "2" and "0x2"
        except ValueError:
            pass
    return out


# ========= Application =========

class QoSTreeController(app_manager.RyuApp):
    """
    QoS + MPLS demo controller (DiffServ -> MPLS EXP mapping)

    - Table 0: classification (ICMP bypass -> goto table1, DSCP->push_mpls or set_queue)
    - Table 1: MAC learning (reactive unicast flows)

    Env variables (optional):
      MPLS_MODE = none | uniform | shortpipe | pipe    # behavior label (only for logging)
      MPLS_INGRESS_DPIDS = "2,3"                      # DPIDs where we push MPLS
      MPLS_EGRESS_DPIDS = "3"                         # DPIDs where we pop MPLS
      MPLS_EXP_EF / MPLS_EXP_AF / MPLS_EXP_BE = ints  # mapping to mpls_tc values
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # DSCP → mpls_exp mapping default
    _DSCP_MAP: Dict[int, int] = {
        46: 5,  # EF -> default EXP 5
        26: 3,  # AF31 -> EXP 3
         0: 0,  # BE -> EXP 0
    }

    def _ingress_dpids(self) -> Set[int]:
        return _parse_dpid_list(_env_flag("MPLS_INGRESS_DPIDS", ""))

    def _egress_dpids(self) -> Set[int]:
        return _parse_dpid_list(_env_flag("MPLS_EGRESS_DPIDS", ""))

    def _mpls_mode(self) -> str:
        return _env_flag("MPLS_MODE", "none").lower()

    def _exp_to_dscp_map(self) -> Dict[int, int]:
        """Odwrócona mapa EXP->DSCP; jeśli clash, bierze największy DSCP."""
        rev: Dict[int, int] = {}
        for dscp, exp in self._DSCP_MAP.items():
            if exp not in rev or dscp > rev[exp]:
                rev[exp] = dscp
        return rev

    def _load_exp_map(self) -> None:
        # override defaults from env if provided
        try:
            ef = _env_flag("MPLS_EXP_EF", "")
            af = _env_flag("MPLS_EXP_AF", "")
            be = _env_flag("MPLS_EXP_BE", "")
            if ef:
                self._DSCP_MAP[46] = int(ef)
            if af:
                self._DSCP_MAP[26] = int(af)
            if be:
                self._DSCP_MAP[0] = int(be)
        except Exception:
            pass

    def __init__(self, *args, **kwargs):
        super(QoSTreeController, self).__init__(*args, **kwargs)

        self.mac_to_port: Dict[int, Dict[str, int]] = {}
        self.host_ports: Dict[int, Set[int]] = {}
        self.graph: Dict[int, Dict[int, Tuple[int, int]]] = {}
        self.sp_tree: Dict[int, Set[int]] = {}
        self.datapaths: Dict[int, object] = {}

        self._load_exp_map()

        self.logger.info(
            "[MPLS] mode=%s ingress=%s egress=%s exp_map=%s",
            self._mpls_mode(), sorted(self._ingress_dpids()) or "ALL",
            sorted(self._egress_dpids()) or "ALL", self._DSCP_MAP,
        )

    # ========= Datapath lifecycle =========

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == 'dead' and dp.id in self.datapaths:
            self.datapaths.pop(dp.id, None)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        p = dp.ofproto_parser

        self.logger.info("[SWITCH] Connected: dpid=%s", hex(dp.id))
        self.datapaths[dp.id] = dp

        # Clear Table 0 and set miss_send_len
        self._purge_table0(dp)
        dp.send_msg(
            p.OFPSetConfig(datapath=dp, miss_send_len=ofp.OFPCML_NO_BUFFER, flags=0)
        )

        # table-miss to controller in T0 and T1
        self._add_table_miss(dp, table_id=0)
        self._add_table_miss(dp, table_id=1)

        # drop LLDP/IPv6 in T0
        self._add_drop(dp, table_id=0, priority=30000, eth_type=ether_types.ETH_TYPE_LLDP)
        self._add_drop(dp, table_id=0, priority=10000, eth_type=ether_types.ETH_TYPE_IPV6)

        # IMPORTANT: ensure ICMP (ping) bypasses MPLS/DSCP rules and goes to T1
        # match eth_type=0x0800 (IP) and ip_proto=1 (ICMP)
        try:
            match_icmp = p.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=1)
            inst = [p.OFPInstructionGotoTable(1)]
            dp.send_msg(
                p.OFPFlowMod(
                    datapath=dp,
                    table_id=0,
                    priority=21000,
                    match=match_icmp,
                    instructions=inst,
                )
            )
            self.logger.info("[MPLS] installed ICMP-bypass on %s", hex(dp.id))
        except Exception as e:
            self.logger.error("[MPLS] failed to install icmp bypass: %s", e)
        try:
            match_arp = p.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
            inst = [p.OFPInstructionGotoTable(1)]
            dp.send_msg(
                p.OFPFlowMod(
                    datapath=dp,
                    table_id=0,
                    priority=20500,
                    match=match_arp,
                    instructions=inst,
                )
            )
            self.logger.info("[MPLS] installed ARP-bypass on %s", hex(dp.id))
        except Exception as e:
            self.logger.error("[MPLS] failed to install ARP bypass: %s", e)

        # Install MPLS rules on ingress/egress DPIDs only.
        try:
            self._install_mpls_or_forwarding(dp)
        except Exception as e:
            self.logger.error("[MPLS] install error on %s: %s", hex(dp.id), e)

        # Default in T0: goto T1 (low priority)
        self._add_default_goto_tbl1(dp)

    # ========= Table helpers =========

    def _add_drop(self, dp, table_id: int, priority: int, eth_type: int) -> None:
        p = dp.ofproto_parser
        match = p.OFPMatch(eth_type=eth_type)
        dp.send_msg(
            p.OFPFlowMod(
                datapath=dp, table_id=table_id, priority=priority, match=match, instructions=[]
            )
        )

    def _add_default_goto_tbl1(self, dp) -> None:
        p = dp.ofproto_parser
        inst = [p.OFPInstructionGotoTable(1)]
        dp.send_msg(
            p.OFPFlowMod(datapath=dp, table_id=0, priority=1, match=p.OFPMatch(), instructions=inst)
        )

    def _add_table_miss(self, dp, table_id: int = 0) -> None:
        ofp = dp.ofproto
        p = dp.ofproto_parser
        actions = [p.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(
            p.OFPFlowMod(datapath=dp, table_id=table_id, priority=0, match=p.OFPMatch(), instructions=inst)
        )



    def _purge_table0(self, dp) -> None:
        ofp = dp.ofproto
        p = dp.ofproto_parser
        dp.send_msg(
            p.OFPFlowMod(
                datapath=dp,
                table_id=0,
                command=ofp.OFPFC_DELETE,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
            )
        )

    # ========= MPLS / DSCP handling =========

    def _install_mpls_or_forwarding(self, dp) -> None:
        ofp = dp.ofproto
        p = dp.ofproto_parser

        dpid = dp.id
        ingress = self._ingress_dpids()
        egress  = self._egress_dpids()
        mode    = self._mpls_mode()  # "uniform" | "shortpipe" | "pipe" | "none"

        # ========== INGRESS ==========
        if not ingress or dpid in ingress:
            for dscp, exp in self._DSCP_MAP.items():
                # IP match po DSCP
                match = p.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_dscp=dscp)

                actions = []
                # Tryby: zawsze push + mpls_tc z DSCP
                actions.append(p.OFPActionPushMpls(ethertype=0x8847))
                actions.append(p.OFPActionSetField(mpls_label=100))
                actions.append(p.OFPActionSetField(mpls_tc=exp))

                # PIPE: nadpisz IP DSCP po push, żeby "rdzeń" był niezależny od IP DSCP
                if mode == "pipe":
                    actions.append(p.OFPActionSetField(ip_dscp=0))  # BE

                inst = [
                    p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
                    p.OFPInstructionGotoTable(1),
                ]

                dp.send_msg(p.OFPFlowMod(
                    datapath=dp, table_id=0, priority=20000,
                    match=match, instructions=inst
                ))
                self.logger.info("[MPLS/%s] dpid=%s ingress: DSCP=%d -> push, EXP=%d%s",
                                 mode, hex(dpid), dscp, exp,
                                 " + ip_dscp=0 (pipe)" if mode == "pipe" else "")

        # ========== EGRESS ==========
        if not egress or dpid in egress:
            # Wspólna akcja pop (pierwsza), a potem ewentualny set ip_dscp
            if mode == "uniform":
                # 3 reguły: match eth_type=mpls + mpls_tc = {EXP} -> pop + set ip_dscp
                rev = self._exp_to_dscp_map()
                for exp, dscp in rev.items():
                    match = p.OFPMatch(eth_type=0x8847, mpls_tc=exp)
                    actions = [
                        p.OFPActionPopMpls(ethertype=0x0800),  # do IPv4
                        p.OFPActionSetField(ip_dscp=dscp),
                    ]
                    inst = [p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
                            p.OFPInstructionGotoTable(1)]
                    dp.send_msg(p.OFPFlowMod(
                        datapath=dp, table_id=0, priority=20010,
                        match=match, instructions=inst
                    ))
                    self.logger.info("[MPLS/%s] dpid=%s egress: EXP=%d -> pop + ip_dscp=%d",
                                     mode, hex(dpid), exp, dscp)

                # Fallback: jakby pojawił się MPLS bez znanego EXP
                match = p.OFPMatch(eth_type=0x8847)
                inst = [p.OFPInstructionActions(
                            ofp.OFPIT_APPLY_ACTIONS,
                            [p.OFPActionPopMpls(ethertype=0x0800)]
                       ),
                       p.OFPInstructionGotoTable(1)]
                dp.send_msg(p.OFPFlowMod(
                    datapath=dp, table_id=0, priority=20005,
                    match=match, instructions=inst
                ))
                self.logger.info("[MPLS/%s] dpid=%s egress: fallback pop",
                                 mode, hex(dpid))

            else:
                # shortpipe/pipe: po prostu pop bez odtwarzania DSCP
                match = p.OFPMatch(eth_type=0x8847)
                inst = [p.OFPInstructionActions(
                            ofp.OFPIT_APPLY_ACTIONS,
                            [p.OFPActionPopMpls(ethertype=0x0800)]
                       ),
                       p.OFPInstructionGotoTable(1)]
                dp.send_msg(p.OFPFlowMod(
                    datapath=dp, table_id=0, priority=20005,
                    match=match, instructions=inst
                ))
                self.logger.info("[MPLS/%s] dpid=%s egress: pop only", mode, hex(dpid))


    # ========= Topology / spanning tree (limited flood) =========

    @set_ev_cls(topo_event.EventSwitchEnter)
    def _switch_enter(self, ev):
        dpid = ev.switch.dp.id
        self.datapaths[dpid] = ev.switch.dp
        self.logger.info("[SWITCH+] %s entered", hex(dpid))

    @set_ev_cls(topo_event.EventSwitchLeave)
    def _switch_leave(self, ev):
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
            self._recompute_spanning_tree()

    @set_ev_cls(topo_event.EventLinkAdd)
    def _link_add(self, ev):
        link = ev.link
        u, v = link.src.dpid, link.dst.dpid
        up, vp = link.src.port_no, link.dst.port_no

        self.logger.info("[LINK+] %s:%s <-> %s:%s", hex(u), up, hex(v), vp)

        self.graph.setdefault(u, {})[v] = (up, vp)
        self.graph.setdefault(v, {})[u] = (vp, up)
        self._recompute_spanning_tree()

    @set_ev_cls(topo_event.EventLinkDelete)
    def _link_delete(self, ev):
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

    def _recompute_spanning_tree(self) -> None:
        """Recompute simple BFS-based spanning tree and allowed ports per DPID."""
        if not self.graph:
            self.sp_tree = {}
            return

        root = min(self.graph.keys())
        visited = {root}
        parent: Dict[int, Optional[int]] = {root: None}

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
            up, _ = self.graph[u][v]
            vp, _ = self.graph[v][u]
            allowed.setdefault(u, set()).add(up)
            allowed.setdefault(v, set()).add(vp)

        self.sp_tree = allowed
        self.logger.info(
            "[TREE] %s",
            {hex(k): sorted(list(v)) for k, v in self.sp_tree.items()}
        )

    # ========= L2 / flooding / packet-in handling =========

    def _arp_host_flood_global(self, in_dp, in_port: int, data: bytes) -> None:
        """Flood ARP to host ports across all DPIDs (skip ingress)."""
        ofp = in_dp.ofproto
        p = in_dp.ofproto_parser

        self.logger.info("[ARP-FLOOD] in_dpid=%s in_port=%s host_ports_snapshot=%s",
                         hex(in_dp.id), in_port,
                         {hex(d): sorted(list(ps)) for d, ps in self.host_ports.items()})

        total_sent = 0
        for dpid, dp in list(self.datapaths.items()):
            ports = sorted(self.host_ports.get(dpid, set()))
            if not ports:
                self.logger.debug("[ARP-FLOOD] skipping dpid=%s (no host ports)", hex(dpid))
                continue
            for port in ports:
                if dpid == in_dp.id and port == in_port:
                    self.logger.debug("[ARP-FLOOD] skip ingress port dpid=%s port=%s", hex(dpid), port)
                    continue
                try:
                    dp.send_msg(
                        p.OFPPacketOut(
                            datapath=dp,
                            buffer_id=ofp.OFP_NO_BUFFER,
                            in_port=ofp.OFPP_CONTROLLER,
                            actions=[p.OFPActionOutput(port)],
                            data=data,
                        )
                    )
                    total_sent += 1
                    self.logger.debug("[ARP-FLOOD] pktout -> dpid=%s port=%s", hex(dpid), port)
                except Exception as e:
                    self.logger.exception("[ARP-FLOOD] error sending pktout to dpid=%s port=%s: %s", hex(dpid), port, e)

        self.logger.info("[ARP-FLOOD] finished, total pktouts sent=%d", total_sent)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        p = dp.ofproto_parser

        dpid = dp.id
        in_port = msg.match.get('in_port')

        # basic header info
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            self.logger.debug("[PKT-IN] no ethernet header, ignoring")
            return

        src, dst, eth_type = eth.src, eth.dst, eth.ethertype

        self.logger.debug("[PKT-IN] dpid=%s in_port=%s eth_type=0x%04x src=%s dst=%s pkt_len=%d",
                          hex(dpid), in_port, eth_type, src, dst, len(msg.data))

        # Already dropped in T0, but double-check
        if eth_type == ether_types.ETH_TYPE_LLDP:
            self.logger.debug("[PKT-IN] LLDP received on dpid=%s port=%s -> ignored (LLDP)", hex(dpid), in_port)
            return

        # show current known datapaths/switches (snapshot)
        self.logger.debug("[STATE] datapaths=%s", [hex(k) for k in self.datapaths.keys()])
        self.logger.debug("[STATE] graph=%s", {hex(k): {hex(u): v for u, v in vs.items()} for k, vs in self.graph.items()})
        self.logger.debug("[STATE] sp_tree=%s", {hex(k): sorted(list(v)) for k, v in self.sp_tree.items()})
        self.logger.debug("[STATE] host_ports=%s", {hex(k): sorted(list(v)) for k, v in self.host_ports.items()})

        # Learn source + qualify host port
        prev = self.mac_to_port.get(dpid, {}).get(src)
        self.mac_to_port.setdefault(dpid, {})[src] = in_port
        if prev is None:
            self.logger.info("[LEARN] dpid=%s learned src=%s -> port=%s", hex(dpid), src, in_port)
        elif prev != in_port:
            self.logger.info("[LEARN] dpid=%s updated src=%s port %s -> %s", hex(dpid), src, prev, in_port)

        # determine if in_port is link->port according to topology graph
        is_link_port = any(u_p == in_port for _, (u_p, v_p) in self.graph.get(dpid, {}).items())
        self.logger.debug("[PORT-TYPE] dpid=%s in_port=%s is_link_port=%s", hex(dpid), in_port, is_link_port)
        if not is_link_port:
            self.host_ports.setdefault(dpid, set()).add(in_port)
            self.logger.debug("[HOST-PORT] added dpid=%s port=%s to host_ports", hex(dpid), in_port)

        # ARP -> flood to host ports globally (as in the first code)
        if eth_type == ether_types.ETH_TYPE_ARP:
            self.logger.info("[PKT-IN-ARP] dpid=%s in_port=%s src=%s dst=%s => ARP flood global", hex(dpid), in_port, src, dst)
            self._arp_host_flood_global(dp, in_port, msg.data)
            return

        # Unicast if we know the output
        if dst in self.mac_to_port.get(dpid, {}):
            out_port = self.mac_to_port[dpid][dst]
            self.logger.info("[UNICAST] dpid=%s dst=%s known -> out_port=%s (installing flow)", hex(dpid), dst, out_port)
            match = p.OFPMatch(eth_dst=dst)
            actions = [p.OFPActionOutput(out_port)]
            inst = [p.OFPInstructionActions(ofp.OFPIT_WRITE_ACTIONS, actions)]

            try:
                dp.send_msg(
                    p.OFPFlowMod(
                        datapath=dp,
                        table_id=1,
                        priority=100,
                        idle_timeout=20,
                        hard_timeout=0,
                        match=match,
                        instructions=inst,
                    )
                )
                self.logger.debug("[FLOWMOD] dpid=%s installed L2 unicast flow dst=%s -> out=%s", hex(dpid), dst, out_port)
            except Exception as e:
                self.logger.exception("[FLOWMOD] error installing flow on dpid=%s dst=%s: %s", hex(dpid), dst, e)

            try:
                dp.send_msg(
                    p.OFPPacketOut(
                        datapath=dp,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        in_port=in_port,
                        actions=actions,
                        data=msg.data,
                    )
                )
                self.logger.debug("[PKT-OUT] unicast pktout sent dpid=%s -> port=%s dst=%s", hex(dpid), out_port, dst)
            except Exception as e:
                self.logger.exception("[PKT-OUT] error sending unicast pktout on dpid=%s: %s", hex(dpid), e)
            return

        # Limited flood: local host ports + spanning-tree ports
        actions = []
        actions_ports = []
        for port in sorted(self.host_ports.get(dpid, set())):
            if port != in_port:
                actions.append(p.OFPActionOutput(port))
                actions_ports.append(port)
        for port in sorted(self.sp_tree.get(dpid, set())):
            if port != in_port:
                actions.append(p.OFPActionOutput(port))
                actions_ports.append(port)

        # debug: if nothing collected, report it
        if not actions:
            self.logger.info("[LIMITED-FLOOD] dpid=%s in_port=%s -> no actions built (host_ports=%s sp_tree=%s).",
                             hex(dpid), in_port,
                             sorted(self.host_ports.get(dpid, set())), sorted(self.sp_tree.get(dpid, set())))
            # optional: do not return here — you may want a fallback flood (see comment in main chat)
        else:
            self.logger.info("[LIMITED-FLOOD] dpid=%s in_port=%s actions_ports=%s dst=%s",
                             hex(dpid), in_port, actions_ports, dst)

        # send PacketOut if actions present
        if actions:
            try:
                dp.send_msg(
                    p.OFPPacketOut(
                        datapath=dp,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        in_port=in_port,
                        actions=actions,
                        data=msg.data,
                    )
                )
                self.logger.debug("[PKT-OUT] flood pktout sent dpid=%s in_port=%s -> ports=%s",
                                  hex(dpid), in_port, actions_ports)
            except Exception as e:
                self.logger.exception("[PKT-OUT] error sending flood pktout on dpid=%s: %s", hex(dpid), e)
