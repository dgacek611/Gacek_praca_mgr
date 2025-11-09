from typing import Dict, Set, Tuple, Optional

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ether_types
from ryu.topology import event as topo_event


class QoSTreeBase(app_manager.RyuApp):
    """
    Bazowa aplikacja QoS z prostym drzewem rozpinającym i ograniczonym floodowaniem.

    Założenia tablic:
      - Tabela 0: klasyfikacja QoS (DSCP -> kolejka / meter), drop LLDP/IPv6,
                  na końcu goto Tabela 1.
      - Tabela 1: klasyczne MAC learning (reaktywne unicast flows).
      - Flood: tylko na porty hostów i porty w drzewie rozpinającym (spanning tree).
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # ========= Inicjalizacja / stan =========

    def __init__(self, *args, **kwargs):
        super(QoSTreeBase, self).__init__(*args, **kwargs)

        # mac_to_port[dpid][mac] -> port_no
        self.mac_to_port: Dict[int, Dict[str, int]] = {}

        # host_ports[dpid] -> zbiór portów prowadzących do hostów (edge)
        self.host_ports: Dict[int, Set[int]] = {}

        # graph[dpid_u][dpid_v] -> (port_u_do_v, port_v_do_u)
        self.graph: Dict[int, Dict[int, Tuple[int, int]]] = {}

        # sp_tree[dpid] -> zbiór portów dopuszczonych przez drzewo rozpinające
        self.sp_tree: Dict[int, Set[int]] = {}

        # datapaths[dpid] -> obiekt datapath
        self.datapaths: Dict[int, object] = {}

    # ========= Cykl życia datapath =========

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        """
        Śledzenie datapathów: dodawanie przy MAIN_DISPATCHER,
        usuwanie przy stanie 'dead'.
        """
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER and dp.id in self.datapaths:
            self.datapaths.pop(dp.id, None)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Konfiguracja początkowa przełącznika:
         - czyszczenie tabeli 0,
         - ustawienie miss_send_len,
         - dodanie table-miss w T0 i T1 (do kontrolera),
         - drop LLDP/IPv6 w T0,
         - domyślne goto T1 w T0.
        """
        dp = ev.msg.datapath
        ofp = dp.ofproto
        p = dp.ofproto_parser

        self.logger.info("[SWITCH] Connected: dpid=%s", hex(dp.id))
        self.datapaths[dp.id] = dp

        # Czyścimy tabelę 0 i konfigurujemy miss_send_len
        self._purge_table0(dp)
        dp.send_msg(
            p.OFPSetConfig(
                datapath=dp,
                miss_send_len=ofp.OFPCML_NO_BUFFER,
                flags=0,
            )
        )

        # Table-miss w T0 i T1 -> do kontrolera (dla debugowania)
        self._add_table_miss(dp, table_id=0)
        self._add_table_miss(dp, table_id=1)

        # Drop LLDP i IPv6 w T0 (żeby nie zaśmiecać statystyk)
        self._add_drop(
            dp,
            table_id=0,
            priority=30000,
            eth_type=ether_types.ETH_TYPE_LLDP,
        )
        self._add_drop(
            dp,
            table_id=0,
            priority=10000,
            eth_type=ether_types.ETH_TYPE_IPV6,
        )

        # Domyślnie w T0: przejście do T1
        self._add_default_goto_tbl1(dp)

    # ========= Pomocnicze dla T0 / T1 =========

    def _add_drop(self, dp, table_id: int, priority: int, eth_type: int) -> None:
        """
        Dodaje regułę dropującą dla wskazanego eth_type w danej tabeli.
        """
        p = dp.ofproto_parser
        match = p.OFPMatch(eth_type=eth_type)
        dp.send_msg(
            p.OFPFlowMod(
                datapath=dp,
                table_id=table_id,
                priority=priority,
                match=match,
                instructions=[],
            )
        )

    def _add_default_goto_tbl1(self, dp) -> None:
        """
        Dodaje w T0 regułę o priorytecie 1: match=ANY -> goto T1.
        """
        p = dp.ofproto_parser
        inst = [p.OFPInstructionGotoTable(1)]
        dp.send_msg(
            p.OFPFlowMod(
                datapath=dp,
                table_id=0,
                priority=1,
                match=p.OFPMatch(),
                instructions=inst,
            )
        )

    def _add_table_miss(self, dp, table_id: int = 0) -> None:
        """
        Dodaje table-miss w podanej tabeli: wszystko do kontrolera.
        """
        ofp = dp.ofproto
        p = dp.ofproto_parser
        actions = [p.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(
            p.OFPFlowMod(
                datapath=dp,
                table_id=table_id,
                priority=0,
                match=p.OFPMatch(),
                instructions=inst,
            )
        )

    def _purge_table0(self, dp) -> None:
        """
        Usuwa wszystkie wpisy z tabeli 0 (OFPFC_DELETE).
        """
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

    # ========= Topologia / drzewo rozpinające (ograniczony flood) =========

    @set_ev_cls(topo_event.EventSwitchEnter)
    def _switch_enter(self, ev):
        """
        Reakcja na pojawienie się przełącznika w topologii (topology discovery).
        """
        dpid = ev.switch.dp.id
        self.datapaths[dpid] = ev.switch.dp
        self.logger.info("[SWITCH+] %s entered", hex(dpid))

    @set_ev_cls(topo_event.EventSwitchLeave)
    def _switch_leave(self, ev):
        """
        Reakcja na zniknięcie przełącznika z topologii:
         - usunięcie z map,
         - aktualizacja grafu,
         - rekalkulacja drzewa rozpinającego.
        """
        dpid = ev.switch.dp.id
        self.logger.info("[SWITCH-] %s left", hex(dpid))

        # Czyścimy stany powiązane z tym dpid
        self.datapaths.pop(dpid, None)
        self.mac_to_port.pop(dpid, None)
        self.host_ports.pop(dpid, None)

        if dpid in self.graph:
            self.graph.pop(dpid, None)
            # Usuwamy krawędzie do dpid z innych węzłów
            for u in list(self.graph.keys()):
                self.graph[u].pop(dpid, None)
                if not self.graph[u]:
                    self.graph.pop(u, None)
            self._recompute_spanning_tree()

    @set_ev_cls(topo_event.EventLinkAdd)
    def _link_add(self, ev):
        """
        Reakcja na dodanie nowego linku w topologii (dwukierunkowo).
        """
        link = ev.link
        u, v = link.src.dpid, link.dst.dpid
        up, vp = link.src.port_no, link.dst.port_no

        self.logger.info("[LINK+] %s:%s <-> %s:%s", hex(u), up, hex(v), vp)

        # Dodajemy krawędź w obu kierunkach: u<->v
        self.graph.setdefault(u, {})[v] = (up, vp)
        self.graph.setdefault(v, {})[u] = (vp, up)

        self._recompute_spanning_tree()

    @set_ev_cls(topo_event.EventLinkDelete)
    def _link_delete(self, ev):
        """
        Reakcja na usunięcie linku w topologii:
         - usunięcie krawędzi z grafu,
         - ponowna budowa drzewa rozpinającego.
        """
        link = ev.link
        u, v = link.src.dpid, link.dst.dpid

        self.logger.info("[LINK-] %s <-> %s", hex(u), hex(v))

        # Usuwamy krawędź u->v
        if u in self.graph and v in self.graph[u]:
            self.graph[u].pop(v, None)
            if not self.graph[u]:
                self.graph.pop(u, None)

        # Usuwamy krawędź v->u (kod zachowany 1:1 z oryginałem)
        if v in self.graph and u in self.graph[v]:
            self.graph[v].pop(u, None)
            if not self.graph[v]:
                self.graph.pop(v, None)

        self._recompute_spanning_tree()

    def _recompute_spanning_tree(self) -> None:
        """
        Przelicza drzewo rozpinające (BFS) oraz zbiór dozwolonych portów
        dla każdego DPID (self.sp_tree).
        """
        if not self.graph:
            self.sp_tree = {}
            return

        # Wybieramy korzeń jako przełącznik o najmniejszym DPID
        root = min(self.graph.keys())
        visited = {root}
        parent: Dict[int, Optional[int]] = {root: None}

        from collections import deque
        q = deque([root])

        # BFS po grafie topologii
        while q:
            u = q.popleft()
            for v in sorted(self.graph.get(u, {}).keys()):
                if v not in visited:
                    visited.add(v)
                    parent[v] = u
                    q.append(v)

        # Wyznaczamy dozwolone porty (krawędzie w drzewie)
        allowed: Dict[int, Set[int]] = {}
        for v, u in parent.items():
            if u is None:
                continue
            # port z u -> v i z v -> u
            up, _ = self.graph[u][v]
            vp, _ = self.graph[v][u]

            allowed.setdefault(u, set()).add(up)
            allowed.setdefault(v, set()).add(vp)

        self.sp_tree = allowed

        # Log w wersji z DPID-ami w hex
        self.logger.info(
            "[TREE] %s",
            {hex(k): sorted(list(v)) for k, v in self.sp_tree.items()},
        )
