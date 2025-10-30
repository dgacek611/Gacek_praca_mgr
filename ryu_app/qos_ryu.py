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
    - Table 0: QoS classification (DSCP -> queue or meter), drop LLDP/IPv6, goto table 1
    - Table 1: MAC learning (reactive unicast flows)
    - Flood: only to host ports and spanning-tree ports

    Mode selected via environment variable:
      QOS_MODE = none | htb | hfsc | meter

    For 'meter' you can restrict DPIDs:
      QOS_METER_DPIDS = "2,3"  (decimal/hex list)

    Meter params in Mb/s and MB (burst):
      QOS_{EF,AF,BE}_MBIT, QOS_{EF,AF,BE}_BURST_MB
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # DSCP → {queue,meter}
    _DSCP_MAP: Dict[int, Dict[str, int]] = {
        46: {"queue": 2, "meter": 1},  # EF
        26: {"queue": 1, "meter": 2},  # AF31
         0: {"queue": 0, "meter": 3},  # BE
    }

    # ========= ENV / QoS configuration =========

    def _qos_mode(self) -> str:
        return _env_flag("QOS_MODE", "none").lower()

    def _meter_dpid_whitelist(self) -> Set[int]:
        return _parse_dpid_list(_env_flag("QOS_METER_DPIDS", ""))

    def _rates_bursts(self) -> Tuple[int, int, int, int, int, int]: 
        """Return (ef_rate, af_rate, be_rate, ef_burst, af_burst, be_burst)."""
        ef_rate = int(_env_flag("QOS_EF_MBIT", "6"))
        af_rate = int(_env_flag("QOS_AF_MBIT", "3"))
        be_rate = int(_env_flag("QOS_BE_MBIT", "1"))
        ef_burst = int(_env_flag("QOS_EF_BURST_MB", "1"))
        af_burst = int(_env_flag("QOS_AF_BURST_MB", "1"))
        be_burst = int(_env_flag("QOS_BE_BURST_MB", "2"))
        return ef_rate, af_rate, be_rate, ef_burst, af_burst, be_burst

    # ========= Init / state =========

    def __init__(self, *args, **kwargs):
        super(QoSTreeController, self).__init__(*args, **kwargs)

        # Runtime state
        self.mac_to_port: Dict[int, Dict[str, int]] = {}
        self.host_ports: Dict[int, Set[int]] = {}
        self.graph: Dict[int, Dict[int, Tuple[int, int]]] = {}
        self.sp_tree: Dict[int, Set[int]] = {}
        self.datapaths: Dict[int, object] = {}

        self.logger.info(
            "[QoS] QOS_MODE=%s, QOS_METER_DPIDS=%s",
            self._qos_mode(),
            sorted(self._meter_dpid_whitelist()) or "ALL",
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

        # Table-miss in T0 and T1 -> to controller (debug)
        self._add_table_miss(dp, table_id=0)
        self._add_table_miss(dp, table_id=1)

        # Drop LLDP and IPv6 in T0 (keep stats clean)
        self._add_drop(dp, table_id=0, priority=30000, eth_type=ether_types.ETH_TYPE_LLDP)
        self._add_drop(dp, table_id=0, priority=10000, eth_type=ether_types.ETH_TYPE_IPV6)

        # Install meters if mode is "meter" and DPID allowed (empty whitelist = ALL)
        mode = self._qos_mode()
        allow = self._meter_dpid_whitelist()
        if mode == "meter" and (not allow or dp.id in allow):
            try:
                self._install_meters(dp)
            except Exception as e:  # noqa: BLE001 (explicit logging in controller)
                self.logger.error(
                    "[QoS/meter] dpid=%s meter install failed: %s", hex(dp.id), e
                )

        # QoS (DSCP -> queue/meter) in T0 + Goto T1
        try:
            self._install_qos_rules(dp)
        except Exception as e:  # noqa: BLE001
            self.logger.error("QoS rules install error: %s", e)

        # Default in T0: Goto T1
        self._add_default_goto_tbl1(dp)

    # ========= Table 0 / 1 helpers =========

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

    # ========= QoS / meters =========

    def _install_meters(self, dp) -> None:
        ofp = dp.ofproto
        p = dp.ofproto_parser

        def kbps(mbps: int) -> int:
            return int(mbps * 1000)

        def kbits(mb: int) -> int:
            return int(mb * 1000)

        EF_ID, AF_ID, BE_ID = 1, 2, 3
        ef_rate, af_rate, be_rate, ef_burst, af_burst, be_burst = self._rates_bursts()

        meters = [
            (EF_ID, kbps(ef_rate), kbits(ef_burst)),
            (AF_ID, kbps(af_rate), kbits(af_burst)),
            (BE_ID, kbps(be_rate), kbits(be_burst)),
        ]

        # Delete existing meters (if any)
        for mid, _, _ in meters:
            req = p.OFPMeterMod(dp, command=ofp.OFPMC_DELETE, flags=0, meter_id=mid, bands=[])
            dp.send_msg(req)

        # Add meters
        for mid, rate_kbps, burst_kbits in meters:
            bands = [p.OFPMeterBandDrop(rate=rate_kbps, burst_size=burst_kbits)]
            flags = ofp.OFPMF_KBPS | ofp.OFPMF_BURST
            mod = p.OFPMeterMod(dp, command=ofp.OFPMC_ADD, flags=flags, meter_id=mid, bands=bands)
            dp.send_msg(mod)
            self.logger.info(
                "[QoS/meter] dpid=%s install meter id=%d rate=%dkbps burst=%dkb",
                hex(dp.id), mid, rate_kbps, burst_kbits
            )

    def _install_qos_rules(self, dp) -> None:
        mode = self._qos_mode()
        if mode not in ("hfsc", "htb", "meter"):
            return

        allow_meters = self._meter_dpid_whitelist()
        if mode == "meter" and allow_meters and dp.id not in allow_meters:
            self.logger.info(
                "[QoS/meter] skipping dpid=%s (not in QOS_METER_DPIDS)", hex(dp.id)
            )
            return

        ofp = dp.ofproto
        p = dp.ofproto_parser

        for dscp, spec in self._DSCP_MAP.items():
            match = p.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_dscp=dscp)

            if mode in ("hfsc", "htb"):
                actions = [p.OFPActionSetQueue(spec["queue"])]
                inst = [
                    p.OFPInstructionActions(ofp.OFPIT_WRITE_ACTIONS, actions),
                    p.OFPInstructionGotoTable(1),
                ]
                target = f"queue={spec['queue']}"
            else:
                inst = [
                    p.OFPInstructionMeter(spec["meter"]),
                    p.OFPInstructionGotoTable(1),
                ]
                target = f"meter={spec['meter']}"

            dp.send_msg(
                p.OFPFlowMod(
                    datapath=dp,
                    table_id=0,
                    priority=20000,
                    match=match,
                    instructions=inst,
                )
            )
            self.logger.info("[QoS/%s] dpid=%s DSCP=%d -> %s", mode, hex(dp.id), dscp, target)

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

    # ========= L2 / flooding =========

    def _arp_host_flood_global(self, in_dp, in_port: int, data: bytes) -> None:
        """Flood ARP to host ports across all DPIDs (skip ingress)."""
        ofp = in_dp.ofproto
        p = in_dp.ofproto_parser

        for dpid, dp in list(self.datapaths.items()):
            for port in sorted(self.host_ports.get(dpid, set())):
                if dpid == in_dp.id and port == in_port:
                    continue
                dp.send_msg(
                    p.OFPPacketOut(
                        datapath=dp,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        in_port=ofp.OFPP_CONTROLLER,
                        actions=[p.OFPActionOutput(port)],
                        data=data,
                    )
                )

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

        # Already dropped in T0, but double-check
        if eth_type == ether_types.ETH_TYPE_LLDP:
            return

        # Learn source + qualify host port
        self.mac_to_port.setdefault(dpid, {})[src] = in_port
        is_link_port = any(u_p == in_port for _, (u_p, v_p) in self.graph.get(dpid, {}).items())
        if not is_link_port:
            self.host_ports.setdefault(dpid, set()).add(in_port)

        # ARP -> flood to host ports globally (as in the first code)
        if eth_type == ether_types.ETH_TYPE_ARP:
            self._arp_host_flood_global(dp, in_port, msg.data)
            return

        # Unicast if we know the output
        if dst in self.mac_to_port.get(dpid, {}):
            out_port = self.mac_to_port[dpid][dst]
            match = p.OFPMatch(eth_dst=dst)
            actions = [p.OFPActionOutput(out_port)]
            inst = [p.OFPInstructionActions(ofp.OFPIT_WRITE_ACTIONS, actions)]

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
            dp.send_msg(
                p.OFPPacketOut(
                    datapath=dp,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    in_port=in_port,
                    actions=actions,
                    data=msg.data,
                )
            )
            return

        # Limited flood: local host ports + spanning-tree ports
        actions = []
        for port in sorted(self.host_ports.get(dpid, set())):
            if port != in_port:
                actions.append(p.OFPActionOutput(port))
        for port in sorted(self.sp_tree.get(dpid, set())):
            if port != in_port:
                actions.append(p.OFPActionOutput(port))

        if actions:
            dp.send_msg(
                p.OFPPacketOut(
                    datapath=dp,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    in_port=in_port,
                    actions=actions,
                    data=msg.data,
                )
            )
