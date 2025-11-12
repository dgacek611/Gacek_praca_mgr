"""
Moduł Ryu MPLS (dziedziczy L2 z ryu_ping.QoSTreeController) z obsługą remarku EXP w rdzeniu.

Tryby MPLS:
- uniform:
    Ingress: PUSH MPLS, EXP z DSCP.
    Core:    opcjonalny remark EXP (statyczny lub dynamiczny).
    Egress:  POP MPLS + odtworzenie DSCP z EXP (EXP wpływa na DSCP).

- pipe:
    Ingress: PUSH MPLS, EXP z DSCP, DSCP w IP nie jest czyszczony.
    Core:    remark EXP tylko w MPLS, DSCP w IP nie jest ruszany.
    Egress:  POP MPLS bez zmiany DSCP (zachowujemy DSCP z wejścia).

- shortpipe:
    Ingress: jak pipe (PUSH MPLS, EXP z DSCP, DSCP w IP zostaje),
             ale tylko dla pakietów z portu hosta (MPLS_INGRESS_HOST_PORT).
    Core:    POP MPLS (PHP) na przełącznikach z MPLS_PHP_DPIDS,
             egress PE widzi już czyste IP bez etykiety.
    Egress:  brak POP (zakładamy, że etykieta została zdjęta w rdzeniu).
"""

import os
from typing import Dict, Set, Optional

from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import ether_types
from ryu.lib.packet import packet as ryu_packet
from ryu.lib.packet import ethernet as ryu_eth
from ryu.ofproto import ofproto_v1_3

from ryu_ping import QoSTreeController


# ===== Stałe i pomocnicze aliasy =====

# Etykiety Ethertype wykorzystywane w regułach
ETH_TYPE_IP = ether_types.ETH_TYPE_IP       # IPv4
ETH_TYPE_ARP = ether_types.ETH_TYPE_ARP     # ARP
ETH_TYPE_MPLS_UC = 0x8847                   # MPLS unicast
ETH_TYPE_IPV4 = 0x0800                      # IPv4 (dla POP MPLS)

# Priorytety przepływów w tabeli 0 – zebrane w jednym miejscu dla czytelności
PRIO_BYPASS_ICMP = 21000
PRIO_BYPASS_ARP = 20500
PRIO_INGRESS_PUSH = 20000
PRIO_EGRESS_UNIFORM_RESTORE = 20010
PRIO_CORE_DYNAMIC_PROBE = 20014
PRIO_CORE_STATIC_REMARK = 20015
PRIO_CORE_PHP = 20020
PRIO_EGRESS_FALLBACK_POP = 20005
PRIO_INGRESS_IP_FALLBACK = 15000


# ===== Funkcje pomocnicze =====

def _env_flag(name: str, default: str = "") -> str:
    """Zwraca wartość zmiennej środowiskowej ze zbędnymi spacjami usuniętymi."""
    return os.environ.get(name, default).strip()


def _parse_int_set(csv: str) -> Set[int]:
    """
    Parsuje listę liczb (dec/hex) rozdzielonych przecinkiem do zbioru int.
    Przykład: "13, 0xd, 0xE" → {13, 14}
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
            out.add(int(tok, 0))  # obsługa dec/hex (np. "0xd")
        except ValueError:
            # ignorujemy niepoprawne wpisy, bez przerywania
            pass
    return out


def _parse_remap(spec: str) -> Dict[int, int]:
    """
    Parsuje mapowanie EXP „a->b,c->d” do słownika {a: b, c: d}.
    Tylko wartości z przedziału 0..7 są akceptowane.
    """
    spec = (spec or "").strip()
    if not spec:
        return {}
    out: Dict[int, int] = {}
    for rule in spec.split(","):
        rule = rule.strip()
        if "->" not in rule:
            continue
        a, b = [x.strip() for x in rule.split("->", 1)]
        try:
            ai, bi = int(a, 0), int(b, 0)
            if 0 <= ai <= 7 and 0 <= bi <= 7:
                out[ai] = bi
        except ValueError:
            continue
    return out


class QoSTreeMPLS(QoSTreeController):
    """
    Kontroler rozszerzający QoSTreeController o MPLS/EXP (remark w rdzeniu).
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Domyślne mapowanie DSCP → EXP (możliwe nadpisanie przez ENV)
    _DSCP_MAP: Dict[int, int] = {
        46: 5,  # EF
        26: 3,  # AF31
        0: 0,   # BE
    }

    # ===== Pobieranie konfiguracji z ENV =====

    def _mpls_mode(self) -> str:
        """Zwraca tryb MPLS: 'uniform' | 'pipe' | 'shortpipe' | 'none'."""
        return _env_flag("MPLS_MODE", "none").lower()

    def _ingress_dpids(self) -> Set[int]:
        """Przełączniki PE (ingress), gdzie wykonujemy PUSH MPLS."""
        return _parse_int_set(_env_flag("MPLS_INGRESS_DPIDS", "0xd,0xe"))

    def _egress_dpids(self) -> Set[int]:
        """
        Przełączniki PE (egress), gdzie kończy się LSP.
        Jeśli brak konfiguracji – przyjmujemy symetrię (to samo co ingress).
        """
        e = _parse_int_set(_env_flag("MPLS_EGRESS_DPIDS", ""))
        return e or self._ingress_dpids()

    def _core_dpids(self) -> Set[int]:
        """
        Przełączniki P (rdzeń). Jeśli zbiór pusty, rdzeń jest wyznaczany
        automatycznie jako: != ingress oraz != egress.
        """
        return _parse_int_set(_env_flag("MPLS_CORE_DPIDS", ""))

    def _php_dpids(self) -> Set[int]:
        """
        Przełączniki, które wykonują PHP (penultimate hop popping) w trybie shortpipe.
        Przykład: MPLS_PHP_DPIDS="0x5" dla s5 (Kraków).
        """
        return _parse_int_set(_env_flag("MPLS_PHP_DPIDS", "0x5"))

    def _ingress_host_port(self) -> Optional[int]:
        """
        Port hosta na przełącznikach PE (domyślnie 1: h1-SP1, h2-SP2).
        Używany do zawężenia reguł PUSH MPLS tylko do pakietów z hosta.
        """
        v = _env_flag("MPLS_INGRESS_HOST_PORT", "1")
        try:
            return int(v)
        except ValueError:
            return None

    def _core_dynamic(self) -> bool:
        """Czy remark EXP w rdzeniu ma być instalowany dynamicznie (PacketIn)."""
        return _env_flag("MPLS_CORE_DYNAMIC", "1").lower() in ("1", "true", "yes", "on")

    def _core_dynamic_limit(self) -> int:
        """Maksymalna liczba przełączników rdzeniowych z dynamicznym remarkiem."""
        try:
            return max(1, int(_env_flag("MPLS_CORE_DYNAMIC_LIMIT", "1")))
        except Exception:
            return 1

    def _label(self) -> int:
        """Wspólna etykieta MPLS używana w demie."""
        try:
            return max(0, int(_env_flag("MPLS_LABEL", "100")))
        except Exception:
            return 100

    def _core_remark_map(self) -> Dict[int, int]:
        """Mapowanie EXP→EXP dla remarku w rdzeniu (statyczne)."""
        return _parse_remap(_env_flag("MPLS_CORE_REMARK", "3->5"))  # domyślnie AF(3)→EF(5)

    def _load_exp_overrides(self) -> None:
        """
        Opcjonalne nadpisanie mapy DSCP→EXP przez ENV:
        - MPLS_EXP_EF (dla DSCP 46),
        - MPLS_EXP_AF (dla DSCP 26),
        - MPLS_EXP_BE (dla DSCP 0).
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
        except Exception:
            # celowo cicho – pozostajemy przy domyślnych mapowaniach
            pass

    def _exp_to_dscp_map(self) -> Dict[int, int]:
        """
        Odwrotna mapa EXP→DSCP. Przy konfliktach preferujemy wyższy DSCP.
        """
        rev: Dict[int, int] = {}
        for dscp, exp in self._DSCP_MAP.items():
            if exp not in rev or dscp > rev[exp]:
                rev[exp] = dscp
        return rev

    # ===== Inicjalizacja cyklu życia kontrolera =====

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._load_exp_overrides()
        self._remarked_core: Set[int] = set()  # przełączniki core, na których już zainstalowano remark
        self.logger.info(
            "[MPLS] mode=%s ingress=%s egress=%s core=%s php=%s dyn=%s limit=%d "
            "label=%d exp=%s remark=%s host_port=%s",
            self._mpls_mode(),
            sorted(self._ingress_dpids()) or "ALL",
            sorted(self._egress_dpids()) or "ALL",
            sorted(self._core_dpids()) or "AUTO(!ingress,!egress)",
            sorted(self._php_dpids()) or "(none)",
            self._core_dynamic(), self._core_dynamic_limit(),
            self._label(),
            dict(self._DSCP_MAP),
            self._core_remark_map() or "(none)",
            self._ingress_host_port(),
        )

    # ===== Obsługa zdarzeń OpenFlow =====

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Instalacja bazowych reguł L2/QoS (z klasy nadrzędnej) oraz reguł MPLS.
        Dodatkowo w table=0: bypass dla ARP i ICMP prosto do table=1.
        """
        super().switch_features_handler(ev)  # bazowe L2/QoS

        dp = ev.msg.datapath
        p = dp.ofproto_parser
        ofp = dp.ofproto

        # --- Bypass dla ICMP oraz ARP (skok do table=1) ---
        try:
            dp.send_msg(p.OFPFlowMod(
                datapath=dp, table_id=0, priority=PRIO_BYPASS_ICMP,
                match=p.OFPMatch(eth_type=ETH_TYPE_IP, ip_proto=1),
                instructions=[p.OFPInstructionGotoTable(1)],
            ))
            dp.send_msg(p.OFPFlowMod(
                datapath=dp, table_id=0, priority=PRIO_BYPASS_ARP,
                match=p.OFPMatch(eth_type=ETH_TYPE_ARP),
                instructions=[p.OFPInstructionGotoTable(1)],
            ))
        except Exception as e:
            self.logger.error("[MPLS] bypass failed on %s: %s", hex(dp.id), e)

        # --- Właściwe reguły MPLS ---
        try:
            self._install_mpls_rules(dp)
        except Exception as e:
            self.logger.error("[MPLS] install failed on %s: %s", hex(dp.id), e)

    # ===== Klasyfikacja roli przełącznika =====

    def _is_core(self, dpid: int) -> bool:
        """
        Zwraca True, jeśli przełącznik należy do rdzenia.
        Jeżeli core nie jest jawnie podany, przyjmujemy: != ingress oraz != egress.
        """
        core = self._core_dpids()
        if core:
            return dpid in core
        return (dpid not in self._ingress_dpids()) and (dpid not in self._egress_dpids())

    # ===== Instalacja reguł MPLS (główna) =====

    def _install_mpls_rules(self, dp) -> None:
        """
        Buduje reguły dla ingress/core/egress zgodnie z aktywnym trybem.
        Logika i priorytety pozostają niezmienione względem wersji pierwotnej.
        """
        ofp = dp.ofproto
        p = dp.ofproto_parser
        dpid = dp.id
        mode = self._mpls_mode()
        label = self._label()
        php_dpids = self._php_dpids()
        host_port = self._ingress_host_port()

        # --- INGRESS (PE) – PUSH MPLS tylko z portu hosta ---
        if not self._ingress_dpids() or dpid in self._ingress_dpids():
            for dscp, exp in self._DSCP_MAP.items():
                # dopasowanie IP + DSCP; preferujemy in_port hosta, ale jeśli niepoprawny – dopasuj globalnie
                match_kwargs = {"eth_type": ETH_TYPE_IP, "ip_dscp": dscp}
                if host_port is not None:
                    match_kwargs["in_port"] = host_port
                match = p.OFPMatch(**match_kwargs)

                actions = [
                    p.OFPActionPushMpls(ethertype=ETH_TYPE_MPLS_UC),
                    p.OFPActionSetField(mpls_label=label),
                    p.OFPActionSetField(mpls_tc=exp),
                ]
                inst = [
                    p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
                    p.OFPInstructionGotoTable(1),
                ]
                dp.send_msg(p.OFPFlowMod(
                    datapath=dp, table_id=0, priority=PRIO_INGRESS_PUSH,
                    match=match, instructions=inst
                ))
                self.logger.info(
                    "[INGRESS/%s] %s in_port=%s DSCP=%d -> push lbl=%d EXP=%d",
                    mode, hex(dpid), host_port, dscp, label, exp
                )

            # Fallback: każdy inny IP (np. z core) -> tylko goto table 1 (bez PUSH)
            dp.send_msg(p.OFPFlowMod(
                datapath=dp, table_id=0, priority=PRIO_INGRESS_IP_FALLBACK,
                match=p.OFPMatch(eth_type=ETH_TYPE_IP),
                instructions=[p.OFPInstructionGotoTable(1)]
            ))
            self.logger.info("[INGRESS/%s] %s fallback IP -> table 1 (bez PUSH)", mode, hex(dpid))

        # --- CORE (P) ---
        if self._is_core(dpid):
            if self._core_dynamic():
                # Dynamiczny remark: pierwszy pakiet MPLS → PacketIn + goto table 1
                match = p.OFPMatch(eth_type=ETH_TYPE_MPLS_UC)
                inst = [
                    p.OFPInstructionActions(
                        ofp.OFPIT_APPLY_ACTIONS,
                        [p.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)],
                    ),
                    p.OFPInstructionGotoTable(1),
                ]
                dp.send_msg(p.OFPFlowMod(
                    datapath=dp, table_id=0, priority=PRIO_CORE_DYNAMIC_PROBE,
                    match=match, instructions=inst
                ))
                self.logger.info("[CORE] %s probe for dynamic remark", hex(dpid))
            else:
                # Statyczny remark EXP→EXP
                for src_exp, dst_exp in self._core_remark_map().items():
                    match = p.OFPMatch(eth_type=ETH_TYPE_MPLS_UC, mpls_tc=src_exp)
                    inst = [
                        p.OFPInstructionActions(
                            ofp.OFPIT_APPLY_ACTIONS,
                            [p.OFPActionSetField(mpls_tc=dst_exp)],
                        ),
                        p.OFPInstructionGotoTable(1),
                    ]
                    dp.send_msg(p.OFPFlowMod(
                        datapath=dp, table_id=0, priority=PRIO_CORE_STATIC_REMARK,
                        match=match, instructions=inst
                    ))
                self.logger.info("[CORE] %s static remark rules installed", hex(dpid))

            # Shortpipe: PHP – POP MPLS tylko na wybranych DPID-ach
            if mode == "shortpipe" and dpid in php_dpids:
                match_php = p.OFPMatch(eth_type=ETH_TYPE_MPLS_UC)
                inst_php = [
                    p.OFPInstructionActions(
                        ofp.OFPIT_APPLY_ACTIONS,
                        [p.OFPActionPopMpls(ethertype=ETH_TYPE_IPV4)],
                    ),
                    p.OFPInstructionGotoTable(1),
                ]
                dp.send_msg(p.OFPFlowMod(
                    datapath=dp, table_id=0, priority=PRIO_CORE_PHP,
                    match=match_php, instructions=inst_php
                ))
                self.logger.info("[CORE/shortpipe] %s PHP pop MPLS", hex(dpid))

        # --- EGRESS (PE) ---
        if not self._egress_dpids() or dpid in self._egress_dpids():
            if mode == "uniform":
                # Uniform: POP + odtworzenie DSCP z EXP
                for exp, dscp in self._exp_to_dscp_map().items():
                    match = p.OFPMatch(eth_type=ETH_TYPE_MPLS_UC, mpls_tc=exp)
                    acts = [
                        p.OFPActionPopMpls(ethertype=ETH_TYPE_IPV4),
                        p.OFPActionSetField(ip_dscp=dscp),
                    ]
                    inst = [
                        p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, acts),
                        p.OFPInstructionGotoTable(1),
                    ]
                    dp.send_msg(p.OFPFlowMod(
                        datapath=dp, table_id=0, priority=PRIO_EGRESS_UNIFORM_RESTORE,
                        match=match, instructions=inst
                    ))

                # Fallback: POP bez odtwarzania DSCP (EXP nie w mapie)
                match_any = p.OFPMatch(eth_type=ETH_TYPE_MPLS_UC)
                inst_any = [
                    p.OFPInstructionActions(
                        ofp.OFPIT_APPLY_ACTIONS,
                        [p.OFPActionPopMpls(ethertype=ETH_TYPE_IPV4)],
                    ),
                    p.OFPInstructionGotoTable(1),
                ]
                dp.send_msg(p.OFPFlowMod(
                    datapath=dp, table_id=0, priority=PRIO_EGRESS_FALLBACK_POP,
                    match=match_any, instructions=inst_any
                ))
                self.logger.info("[EGRESS/uniform] %s pop+restore DSCP", hex(dpid))

            elif mode == "pipe":
                # Pipe: POP, DSCP zostaje z wejścia
                match = p.OFPMatch(eth_type=ETH_TYPE_MPLS_UC)
                inst = [
                    p.OFPInstructionActions(
                        ofp.OFPIT_APPLY_ACTIONS,
                        [p.OFPActionPopMpls(ethertype=ETH_TYPE_IPV4)],
                    ),
                    p.OFPInstructionGotoTable(1),
                ]
                dp.send_msg(p.OFPFlowMod(
                    datapath=dp, table_id=0, priority=PRIO_EGRESS_FALLBACK_POP,
                    match=match, instructions=inst
                ))
                self.logger.info("[EGRESS/pipe] %s pop only (preserve DSCP)", hex(dpid))

            elif mode == "shortpipe":
                # Shortpipe: POP wykonany w rdzeniu (PHP) – tutaj nic MPLS-owego nie robimy
                self.logger.info("[EGRESS/shortpipe] %s no MPLS pop (PHP in core)", hex(dpid))

            else:
                # Inne tryby / brak trybu: zachowanie awaryjne – POP tylko
                match = p.OFPMatch(eth_type=ETH_TYPE_MPLS_UC)
                inst = [
                    p.OFPInstructionActions(
                        ofp.OFPIT_APPLY_ACTIONS,
                        [p.OFPActionPopMpls(ethertype=ETH_TYPE_IPV4)],
                    ),
                    p.OFPInstructionGotoTable(1),
                ]
                dp.send_msg(p.OFPFlowMod(
                    datapath=dp, table_id=0, priority=PRIO_EGRESS_FALLBACK_POP,
                    match=match, instructions=inst
                ))
                self.logger.info("[EGRESS/%s] %s pop only (fallback)", mode, hex(dpid))

    # ===== Dynamiczny remark EXP (obsługa PacketIn z rdzenia) =====

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _on_packet_in_dynamic_remark(self, ev):
        """
        Jeśli włączony jest dynamiczny remark i nie przekroczono limitu,
        pierwszy pakiet MPLS z danego przełącznika rdzeniowego powoduje
        instalację reguł remarku EXP→EXP (zgodnie z mapą z ENV).
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

        # Sprawdzamy, czy to faktycznie pakiet MPLS (0x8847)
        try:
            pkt = ryu_packet.Packet(msg.data)
            eth = pkt.get_protocol(ryu_eth.ethernet)
            if not eth or eth.ethertype != ETH_TYPE_MPLS_UC:
                return
        except Exception:
            return

        # Remark już zainstalowany na tym DPID – nic nie robimy
        if dpid in self._remarked_core:
            return

        p = dp.ofproto_parser
        ofp = dp.ofproto

        # Instalujemy reguły statyczne remarku (EXP→EXP) zgodnie z mapą
        for src_exp, dst_exp in self._core_remark_map().items():
            match = p.OFPMatch(eth_type=ETH_TYPE_MPLS_UC, mpls_tc=src_exp)
            inst = [
                p.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [p.OFPActionSetField(mpls_tc=dst_exp)],
                ),
                p.OFPInstructionGotoTable(1),
            ]
            dp.send_msg(p.OFPFlowMod(
                datapath=dp, table_id=0, priority=PRIO_CORE_STATIC_REMARK,
                match=match, instructions=inst
            ))

        # Oznaczamy przełącznik jako „obsłużony” i logujemy postęp
        self._remarked_core.add(dpid)
        self.logger.info(
            "[DYNAMIC] remark installed on core %s (%d/%d)",
            hex(dpid), len(self._remarked_core), self._core_dynamic_limit()
        )
