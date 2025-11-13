import os
from typing import Dict, Set, Optional, List, Tuple

from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import ether_types
from ryu.lib.packet import packet as ryu_packet
from ryu.lib.packet import ethernet as ryu_eth
from ryu.ofproto import ofproto_v1_3

from ryu_ping import QoSTreeController


# ============================================================
#  Pomocnicze funkcje środowiskowe / parsujące
# ============================================================


def _env_flag(name: str, default: str = "") -> str:
    """Zwraca wartość zmiennej środowiskowej (bez spacji dookoła)."""
    return os.environ.get(name, default).strip()


def _parse_int_set(csv: str) -> Set[int]:
    """
    Parsuje listę liczb całkowitych (dec/hex) rozdzielonych przecinkami,
    np. "0x1,0x2,10" → {1, 2, 10}.
    """
    s = (csv or "").strip()
    if not s:
        return set()

    out: Set[int] = set()
    for tok in s.split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            out.add(int(tok, 0))  # obsługa zapisu dziesiętnego i heks.
        except ValueError:
            continue
    return out


def _parse_remap(spec: str) -> Dict[int, int]:
    """
    Parsuje mapowanie EXP→EXP w formacie "a->b,c->d",
    np. "0->1,3->5" → {0:1, 3:5}.
    """
    spec = (spec or "").strip()
    if not spec:
        return {}

    out: Dict[int, int] = {}
    for rule in spec.split(","):
        rule = rule.strip()
        if "->" not in rule:
            continue
        lhs, rhs = [x.strip() for x in rule.split("->", 1)]
        try:
            src, dst = int(lhs, 0), int(rhs, 0)
        except ValueError:
            continue
        if 0 <= src <= 7 and 0 <= dst <= 7:
            out[src] = dst
    return out


def _parse_static_fwd(spec: str) -> Dict[int, List[Tuple[int, int]]]:
    """
    Parsuje statyczne przekierowania LSP z env, np.:

        "0x3:1->2,2->1;0x6:1->3,3->1"

    → {
        3: [(1,2), (2,1)],
        6: [(1,3), (3,1)],
      }

    gdzie:
      - klucz: DPID przełącznika,
      - wartość: lista par (in_port, out_port).
    """
    spec = (spec or "").strip()
    if not spec:
        return {}

    out: Dict[int, List[Tuple[int, int]]] = {}
    for sw_part in spec.split(";"):
        sw_part = sw_part.strip()
        if not sw_part or ":" not in sw_part:
            continue

        dpid_str, rules_str = sw_part.split(":", 1)
        try:
            dpid = int(dpid_str, 0)
        except ValueError:
            continue

        pairs: List[Tuple[int, int]] = []
        for rule in rules_str.split(","):
            rule = rule.strip()
            if "->" not in rule:
                continue
            inp_str, outp_str = rule.split("->", 1)
            try:
                inp = int(inp_str, 0)
                outp = int(outp_str, 0)
            except ValueError:
                continue
            pairs.append((inp, outp))

        if pairs:
            out[dpid] = pairs

    return out


# ============================================================
#  Klasa kontrolera MPLS
# ============================================================


class QoSTreeMPLS(QoSTreeController):
    """
    Kontroler rozszerzający QoSTreeController o obsługę MPLS/EXP
    (push/POP, mapowanie DSCP↔EXP, remark w rdzeniu, tryby uniform/pipe/shortpipe).
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # DSCP → EXP (domyślne mapowanie)
    _DSCP_MAP: Dict[int, int] = {
        46: 5,  # EF
        26: 3,  # AF31
        0: 0,   # BE
    }

    # --------------------------------------------------------
    #  Gettery konfiguracji z env
    # --------------------------------------------------------

    def _mpls_mode(self) -> str:
        """Zwraca tryb MPLS: uniform / pipe / shortpipe / none."""
        return _env_flag("MPLS_MODE", "none").lower()

    def _ingress_dpids(self) -> Set[int]:
        """Zestaw DPID-ów, na których wykonywany jest PUSH MPLS (PE-INGRESS)."""
        return _parse_int_set(_env_flag("MPLS_INGRESS_DPIDS", "0xd"))

    def _egress_dpids(self) -> Set[int]:
        """
        Zestaw DPID-ów, na których kończy się LSP (PE-EGRESS).
        Jeśli nie podano MPLS_EGRESS_DPIDS, zakłada INGRESS=EGRESS.
        """
        egress = _parse_int_set(_env_flag("MPLS_EGRESS_DPIDS", "0xe"))
        return egress or self._ingress_dpids()

    def _core_dpids(self) -> Set[int]:
        """
        Zestaw DPID-ów rdzenia (P). Jeśli pusty, rdzeń jest traktowany jako
        wszystkie przełączniki, które nie są ani ingress, ani egress.
        """
        return _parse_int_set(_env_flag("MPLS_CORE_DPIDS", ""))

    def _php_dpids(self) -> Set[int]:
        """
        Zestaw DPID-ów, które mają wykonywać PHP (penultimate hop popping)
        w trybie shortpipe, np. MPLS_PHP_DPIDS="0x5" dla s5 (Kraków).
        """
        return _parse_int_set(_env_flag("MPLS_PHP_DPIDS", ""))

    def _ingress_host_port(self) -> Optional[int]:
        """
        Port hosta na przełącznikach PE (domyślnie 1: h1-SP1, h2-SP2).
        Używany do zawężenia reguł PUSH MPLS tylko do pakietów z portu hosta.
        """
        value = _env_flag("MPLS_INGRESS_HOST_PORT", "1")
        try:
            return int(value)
        except ValueError:
            return None

    # --- specyficzne parametry dla s1 (FF / TE) ---

    def _s1_dpid(self) -> int:
        """DPID przełącznika s1 (domyślnie 0x1)."""
        try:
            return int(_env_flag("MPLS_S1_DPID", "0x1"), 0)
        except ValueError:
            return 1

    def _s1_port_be(self) -> int:
        """Port dla EXP=0 (BE), np. s1-eth2."""
        return int(_env_flag("MPLS_S1_PORT_BE", "2"))

    def _s1_port_ef(self) -> int:
        """Port dla EXP=5 (EF), np. s1-eth1."""
        return int(_env_flag("MPLS_S1_PORT_EF", "1"))

    def _s1_port_af(self) -> int:
        """Port dla EXP=3 (AF), np. s1-eth3 (trasa główna w FF)."""
        return int(_env_flag("MPLS_S1_PORT_AF", "3"))

    # --- dynamiczny remark w rdzeniu ---

    def _core_dynamic(self) -> bool:
        """
        Czy w rdzeniu włączony jest dynamiczny remark (PacketIn przy pierwszym MPLS).
        Domyślnie wyłączony (0).
        """
        return _env_flag("MPLS_CORE_DYNAMIC", "0").lower() in ("1", "true", "yes", "on")

    def _core_dynamic_limit(self) -> int:
        """Limit liczby przełączników rdzenia, na których instalujemy dynamiczny remark."""
        try:
            return max(1, int(_env_flag("MPLS_CORE_DYNAMIC_LIMIT", "1")))
        except Exception:  # noqa: BLE001
            return 1

    def _label(self) -> int:
        """Etykieta MPLS używana w LSP (domyślnie 100)."""
        try:
            return max(0, int(_env_flag("MPLS_LABEL", "100")))
        except Exception:  # noqa: BLE001
            return 100

    def _core_remark_map(self) -> Dict[int, int]:
        """Statyczna mapa remarku EXP w rdzeniu (domyślnie pusta)."""
        return _parse_remap(_env_flag("MPLS_CORE_REMARK", ""))

    def _load_exp_overrides(self) -> None:
        """
        Opcjonalnie nadpisuje mapowanie DSCP→EXP na podstawie zmiennych środowiskowych:
        - MPLS_EXP_EF
        - MPLS_EXP_AF
        - MPLS_EXP_BE
        """
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
        except Exception:  # noqa: BLE001
            # w razie błędu zostawiamy domyślne mapowanie
            pass

    def _exp_to_dscp_map(self) -> Dict[int, int]:
        """
        Odwrócone mapowanie EXP→DSCP.
        Przy konfliktach wybieramy wyższy DSCP dla danego EXP.
        """
        rev: Dict[int, int] = {}
        for dscp, exp in self._DSCP_MAP.items():
            if exp not in rev or dscp > rev[exp]:
                rev[exp] = dscp
        return rev

    # --------------------------------------------------------
    #  Życie kontrolera
    # --------------------------------------------------------

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._load_exp_overrides()
        self._remarked_core: Set[int] = set()

        self.logger.info(
            "[MPLS] mode=%s ingress=%s egress=%s core=%s php=%s "
            "dyn=%s limit=%d label=%d exp=%s remark=%s host_port=%s",
            self._mpls_mode(),
            sorted(self._ingress_dpids()) or "ALL",
            sorted(self._egress_dpids()) or "ALL",
            sorted(self._core_dpids()) or "AUTO(!ingress,!egress)",
            sorted(self._php_dpids()) or "(none)",
            self._core_dynamic(),
            self._core_dynamic_limit(),
            self._label(),
            dict(self._DSCP_MAP),
            self._core_remark_map() or "(none)",
            self._ingress_host_port(),
        )

    # --------------------------------------------------------
    #  Pomocnicze narzędzia OpenFlow
    # --------------------------------------------------------

    @staticmethod
    def _add_flow(dp, match, instructions, priority: int, table_id: int = 0) -> None:
        """Prosty wrapper do instalowania przepływów."""
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        flow_mod = parser.OFPFlowMod(
            datapath=dp,
            table_id=table_id,
            priority=priority,
            match=match,
            instructions=instructions,
        )
        dp.send_msg(flow_mod)

    @staticmethod
    def _add_ff_group(
        dp,
        group_id: int,
        main_port: int,
        backup_port: int,
    ) -> None:
        """
        Tworzy grupę typu Fast-Failover z dwoma wyjściami:
        - kubełek główny na main_port,
        - kubełek zapasowy na backup_port.
        """
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        bucket_main = parser.OFPBucket(
            watch_port=main_port,
            watch_group=ofp.OFPG_ANY,
            actions=[parser.OFPActionOutput(main_port)],
        )
        bucket_backup = parser.OFPBucket(
            watch_port=backup_port,
            watch_group=ofp.OFPG_ANY,
            actions=[parser.OFPActionOutput(backup_port)],
        )

        group_mod = parser.OFPGroupMod(
            datapath=dp,
            command=ofp.OFPGC_ADD,
            type_=ofp.OFPGT_FF,
            group_id=group_id,
            buckets=[bucket_main, bucket_backup],
        )
        dp.send_msg(group_mod)

    # --------------------------------------------------------
    #  Obsługa EventOFPSwitchFeatures
    # --------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev) -> None:
        """
        Instalacja bazowych reguł L2/QoS (przez QoSTreeController),
        a następnie reguł specyficznych dla MPLS (bypass ARP/ICMP, MPLS).
        """
        # bazowe L2/QoS
        super().switch_features_handler(ev)

        dp = ev.msg.datapath
        parser = dp.ofproto_parser

        # bypass: ARP + ICMP bezpośrednio do table=1
        try:
            match_icmp = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ip_proto=1,
            )
            inst_icmp = [parser.OFPInstructionGotoTable(1)]
            self._add_flow(dp, match_icmp, inst_icmp, priority=21000)

            match_arp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
            inst_arp = [parser.OFPInstructionGotoTable(1)]
            self._add_flow(dp, match_arp, inst_arp, priority=20500)
        except Exception as exc:  # noqa: BLE001
            self.logger.error(
                "[MPLS] bypass failed on %s: %s", hex(dp.id), exc
            )

        # instalacja logiki MPLS
        try:
            self._install_mpls_rules(dp)
        except Exception as exc:  # noqa: BLE001
            self.logger.error(
                "[MPLS] install failed on %s: %s", hex(dp.id), exc
            )

    # --------------------------------------------------------
    #  Klasyfikacja przełączników
    # --------------------------------------------------------

    def _is_core(self, dpid: int) -> bool:
        """
        Zwraca True, jeśli dany DPID jest traktowany jako przełącznik rdzeniowy (P).
        """
        core = self._core_dpids()
        if core:
            return dpid in core

        # domyślnie: core = wszystko, co nie jest ingress ani egress
        return dpid not in self._ingress_dpids() and dpid not in self._egress_dpids()

    # --------------------------------------------------------
    #  Instalacja reguł MPLS
    # --------------------------------------------------------

    def _install_s1_special_rules(self, dp) -> None:
        """
        Instalacja reguł specyficznych dla s1:
        - grupa Fast-Failover dla ruchu EXP=3 (AF),
        - proste przekierowanie EXP=0 (BE) i EXP=5 (EF) na odpowiednie porty.
        """
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        be_port = self._s1_port_be()  # EXP=0
        ef_port = self._s1_port_ef()  # EXP=5
        af_port = self._s1_port_af()  # EXP=3

        group_id = 10  # identyfikator grupy FF dla AF

        # Grupa FF: AF → main (af_port), backup (ef_port)
        self._add_ff_group(dp, group_id, main_port=af_port, backup_port=ef_port)
        self.logger.info(
            "[s1] FF group=%d main=port%d backup=port%d",
            group_id,
            af_port,
            ef_port,
        )

        # EXP=0 (BE) → be_port
        match_be = parser.OFPMatch(eth_type=0x8847, mpls_tc=0)
        inst_be = [
            parser.OFPInstructionActions(
                ofp.OFPIT_APPLY_ACTIONS,
                [parser.OFPActionOutput(be_port)],
            )
        ]
        self._add_flow(dp, match_be, inst_be, priority=20030)

        # EXP=5 (EF) → ef_port
        match_ef = parser.OFPMatch(eth_type=0x8847, mpls_tc=5)
        inst_ef = [
            parser.OFPInstructionActions(
                ofp.OFPIT_APPLY_ACTIONS,
                [parser.OFPActionOutput(ef_port)],
            )
        ]
        self._add_flow(dp, match_ef, inst_ef, priority=20030)

        # EXP=3 (AF) → grupa FF
        match_af = parser.OFPMatch(eth_type=0x8847, mpls_tc=3)
        inst_af = [
            parser.OFPInstructionActions(
                ofp.OFPIT_APPLY_ACTIONS,
                [parser.OFPActionGroup(group_id)],
            )
        ]
        self._add_flow(dp, match_af, inst_af, priority=20030)

        self.logger.info(
            "[s1] MPLS EXP routing: tc0->%d tc5->%d tc3->FF(group %d)",
            be_port,
            ef_port,
            group_id,
        )

    def _install_static_lsp_for_class(
        self,
        dp,
        label: int,
        exp: Optional[int],
        rules: List[Tuple[int, int]],
        priority: int,
    ) -> None:
        """
        Instalacja statycznych LSP dla danej klasy (EXP) na przełączniku:
        - label: etykieta MPLS,
        - exp: wartość EXP przypisana klasie,
        - rules: lista (in_port, out_port).
        """
        if exp is None:
            return

        ofp = dp.ofproto
        parser = dp.ofproto_parser

        for in_port, out_port in rules:
            match = parser.OFPMatch(
                eth_type=0x8847,
                mpls_label=label,
                mpls_tc=exp,
                in_port=in_port,
            )
            actions = [parser.OFPActionOutput(out_port)]
            inst = [
                parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    actions,
                )
            ]
            self._add_flow(dp, match, inst, priority=priority)

    def _install_ingress_rules(self, dp, label: int, mode: str) -> None:
        """
        Reguły INGRESS (PE):
        - push MPLS dla UDP z host_port (DSCP→EXP),
        - fallback: całe IP → table 1.
        """
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        host_port = self._ingress_host_port()

        # PUSH MPLS dla UDP z DSCP mapowanym na EXP
        for dscp, exp in self._DSCP_MAP.items():
            if host_port is not None:
                match = parser.OFPMatch(
                    in_port=host_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ip_proto=17,  # UDP
                    ip_dscp=dscp,
                )
            else:
                # fallback gdy host_port nie jest poprawny
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ip_proto=17,  # UDP
                    ip_dscp=dscp,
                )

            actions = [
                parser.OFPActionPushMpls(ethertype=0x8847),
                parser.OFPActionSetField(mpls_label=label),
                parser.OFPActionSetField(mpls_tc=exp),
            ]
            inst = [
                parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
                parser.OFPInstructionGotoTable(1),
            ]
            self._add_flow(dp, match, inst, priority=20000)

            self.logger.info(
                "[INGRESS/%s] %s in_port=%s UDP DSCP=%d -> push lbl=%d EXP=%d",
                mode,
                hex(dp.id),
                host_port,
                dscp,
                label,
                exp,
            )

        # fallback: całe IP (TCP/UDP z innych portów/DSCP) → tylko table 1
        match_ip = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP)
        inst_ip = [parser.OFPInstructionGotoTable(1)]
        self._add_flow(dp, match_ip, inst_ip, priority=15000)

        self.logger.info(
            "[INGRESS/%s] %s fallback IP -> table 1 (bez PUSH)",
            mode,
            hex(dp.id),
        )

    def _install_core_rules(self, dp, mode: str) -> None:
        """
        Reguły CORE (P):
        - dynamiczny lub statyczny remark EXP,
        - w shortpipe: PHP (POP MPLS) na wybranych DPID-ach.
        """
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        dpid = dp.id

        if self._core_dynamic():
            # dynamiczny remark – pierwszy MPLS trafia do kontrolera
            match = parser.OFPMatch(eth_type=0x8847)
            inst = [
                parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [
                        parser.OFPActionOutput(
                            ofp.OFPP_CONTROLLER,
                            ofp.OFPCML_NO_BUFFER,
                        )
                    ],
                ),
                parser.OFPInstructionGotoTable(1),
            ]
            self._add_flow(dp, match, inst, priority=20014)
            self.logger.info(
                "[CORE] %s probe for dynamic remark", hex(dpid)
            )
        else:
            # statyczny remark według mapy MPLS_CORE_REMARK
            remark_map = self._core_remark_map()
            for src_exp, dst_exp in remark_map.items():
                match = parser.OFPMatch(eth_type=0x8847, mpls_tc=src_exp)
                inst = [
                    parser.OFPInstructionActions(
                        ofp.OFPIT_APPLY_ACTIONS,
                        [parser.OFPActionSetField(mpls_tc=dst_exp)],
                    ),
                    parser.OFPInstructionGotoTable(1),
                ]
                self._add_flow(dp, match, inst, priority=20015)

            if remark_map:
                self.logger.info(
                    "[CORE] %s static remark rules installed", hex(dpid)
                )

        # shortpipe: PHP – POP MPLS w rdzeniu (penultimate hop)
        if mode == "shortpipe" and dpid in self._php_dpids():
            match_php = parser.OFPMatch(eth_type=0x8847)
            inst_php = [
                parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [parser.OFPActionPopMpls(ethertype=0x0800)],
                ),
                parser.OFPInstructionGotoTable(1),
            ]
            self._add_flow(dp, match_php, inst_php, priority=20020)
            self.logger.info(
                "[CORE/shortpipe] %s PHP pop MPLS", hex(dpid)
            )

    def _install_egress_rules(self, dp, mode: str) -> None:
        """
        Reguły EGRESS (PE) w zależności od trybu:
        - uniform: POP MPLS + przywrócenie DSCP z EXP,
        - pipe: POP MPLS, DSCP bez zmian,
        - shortpipe: zakładamy POP w rdzeniu (PHP),
        - inne: POP MPLS jako fallback.
        """
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        dpid = dp.id

        if mode == "uniform":
            # POP + odtworzenie DSCP z EXP
            for exp, dscp in self._exp_to_dscp_map().items():
                match = parser.OFPMatch(eth_type=0x8847, mpls_tc=exp)
                actions = [
                    parser.OFPActionPopMpls(ethertype=0x0800),
                    parser.OFPActionSetField(ip_dscp=dscp),
                ]
                inst = [
                    parser.OFPInstructionActions(
                        ofp.OFPIT_APPLY_ACTIONS,
                        actions,
                    ),
                    parser.OFPInstructionGotoTable(1),
                ]
                self._add_flow(dp, match, inst, priority=20010)

            # fallback – EXP nieznany: POP bez zmiany DSCP
            match_any = parser.OFPMatch(eth_type=0x8847)
            inst_any = [
                parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [parser.OFPActionPopMpls(ethertype=0x0800)],
                ),
                parser.OFPInstructionGotoTable(1),
            ]
            self._add_flow(dp, match_any, inst_any, priority=20005)

            self.logger.info(
                "[EGRESS/uniform] %s pop+restore DSCP", hex(dpid)
            )

        elif mode == "pipe":
            # POP MPLS, DSCP pozostaje z wejścia
            match = parser.OFPMatch(eth_type=0x8847)
            inst = [
                parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [parser.OFPActionPopMpls(ethertype=0x0800)],
                ),
                parser.OFPInstructionGotoTable(1),
            ]
            self._add_flow(dp, match, inst, priority=20005)
            self.logger.info(
                "[EGRESS/pipe] %s pop only (preserve DSCP)", hex(dpid)
            )

        elif mode == "shortpipe":
            # shortpipe: etykieta powinna zostać zdjęta w rdzeniu (PHP)
            self.logger.info(
                "[EGRESS/shortpipe] %s no MPLS pop (PHP in core)", hex(dpid)
            )

        else:
            # fallback: POP MPLS we wszystkich pozostałych trybach
            match = parser.OFPMatch(eth_type=0x8847)
            inst = [
                parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [parser.OFPActionPopMpls(ethertype=0x0800)],
                ),
                parser.OFPInstructionGotoTable(1),
            ]
            self._add_flow(dp, match, inst, priority=20005)
            self.logger.info(
                "[EGRESS/%s] %s pop only (fallback)", mode, hex(dpid)
            )

    def _install_mpls_rules(self, dp) -> None:
        """
        Główna funkcja instalująca reguły MPLS na przełączniku:
        - s1: specjalne reguły FF + routing po EXP,
        - statyczne LSP dla klas BE/AF/EF,
        - reguły ingress / core / egress w zależności od trybu.
        """
        dpid = dp.id
        mode = self._mpls_mode()
        label = self._label()

        # --- s1: specjalny przypadek (EXP routing + grupa FF) ---
        if dpid == self._s1_dpid():
            self._install_s1_special_rules(dp)

        # --- statyczne LSP dla BE/AF/EF (poza s1) ---
        be_map = _parse_static_fwd(
            _env_flag(
                "MPLS_BE_FWD",
                "0x3:1->3,3->1;0xA:1->2,2->1;0x8:2->3,3->2;"
                "0xC:3->1,1->3;0x4:3->1,1->3;0x5:1->4,4->1",
            )
        )
        af_map = _parse_static_fwd(
            _env_flag(
                "MPLS_AF_FWD",
                "0x6:3->1,1->3;0x9:2->1,1->2;0xB:1->3,3->1;"
                "0x5:2->4,3->4,4->2,4->3",
            )
        )
        ef_map = _parse_static_fwd(
            _env_flag(
                "MPLS_EF_FWD",
                "0xB:1->3,3->1;0x5:3->4,4->3",
            )
        )

        if dpid != self._s1_dpid():
            exp_be = self._DSCP_MAP.get(0)
            exp_af = self._DSCP_MAP.get(26)
            exp_ef = self._DSCP_MAP.get(46)

            be_rules = be_map.get(dpid, [])
            af_rules = af_map.get(dpid, [])
            ef_rules = ef_map.get(dpid, [])

            self._install_static_lsp_for_class(
                dp, label, exp_be, be_rules, priority=20025
            )
            self._install_static_lsp_for_class(
                dp, label, exp_af, af_rules, priority=20025
            )
            self._install_static_lsp_for_class(
                dp, label, exp_ef, ef_rules, priority=20025
            )

            if be_rules or af_rules or ef_rules:
                self.logger.info(
                    "[MPLS/static] %s BE=%d AF=%d EF=%d rules",
                    hex(dpid),
                    len(be_rules),
                    len(af_rules),
                    len(ef_rules),
                )

        # --- INGRESS (PE) – PUSH MPLS tylko na ingress DPIDs ---
        if not self._ingress_dpids() or dpid in self._ingress_dpids():
            self._install_ingress_rules(dp, label, mode)

        # --- CORE (P) ---
        if self._is_core(dpid):
            self._install_core_rules(dp, mode)

        # --- EGRESS (PE) ---
        if not self._egress_dpids() or dpid in self._egress_dpids():
            self._install_egress_rules(dp, mode)

    # --------------------------------------------------------
    #  Dynamiczny remark EXP (PacketIn z rdzenia)
    # --------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _on_packet_in_dynamic_remark(self, ev) -> None:
        """
        Obsługa PacketIn z przełączników rdzeniowych (CORE) w trybie dynamicznego remarku:
        - pierwszy napotkany przełącznik MPLS w rdzeniu instaluję reguły remarku
          według mapy MPLS_CORE_REMARK, po czym przestaje generować PacketIn.
        """
        if not self._core_dynamic():
            return
        if len(self._remarked_core) >= self._core_dynamic_limit():
            return

        msg = ev.msg
        dp = msg.datapath
        dpid = dp.id

        if not self._is_core(dpid):
            return

        # sprawdzamy, czy to MPLS
        try:
            pkt = ryu_packet.Packet(msg.data)
            eth = pkt.get_protocol(ryu_eth.ethernet)
            if not eth or eth.ethertype != 0x8847:
                return
        except Exception:  # noqa: BLE001
            return

        if dpid in self._remarked_core:
            return

        parser = dp.ofproto_parser
        ofp = dp.ofproto

        for src_exp, dst_exp in self._core_remark_map().items():
            match = parser.OFPMatch(eth_type=0x8847, mpls_tc=src_exp)
            inst = [
                parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [parser.OFPActionSetField(mpls_tc=dst_exp)],
                ),
                parser.OFPInstructionGotoTable(1),
            ]
            self._add_flow(dp, match, inst, priority=20015)

        self._remarked_core.add(dpid)
        self.logger.info(
            "[DYNAMIC] remark installed on core %s (%d/%d)",
            hex(dpid),
            len(self._remarked_core),
            self._core_dynamic_limit(),
        )
