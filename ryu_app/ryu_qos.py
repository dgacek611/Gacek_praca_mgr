from typing import Set
import os

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3

from ryu_ping import QoSTreeController  # baza L2


# ------- Pomocnicze funkcje do ENV -------

def _env_flag(key: str, default: str = "") -> str:
    """
    Pobierz zmienną środowiskową jako tekst.
    Zwróć `default`, jeżeli zmienna nie istnieje lub jest pusta/biała.
    """
    v = os.environ.get(key)
    return v if v is not None and v.strip() != "" else default


def _env_int(key: str, default: int) -> int:
    """
    Pobierz zmienną środowiskową i zrzutuj ją na int.
    W przypadku błędu lub braku zmiennej zwróć wartość domyślną.
    """
    v = _env_flag(key)
    try:
        return int(v)
    except Exception:
        return default


def _parse_dpid_list(s: str) -> Set[int]:
    """
    Parsuje listę DPID-ów z tekstu w formacie:
      - rozdzielane przecinkami, np. "0xd, 0xe, 13"
      - pojedyncze wartości mogą być w hex (0x...) lub w dziesiętnym.
    Błędne elementy są ignorowane.
    """
    out: Set[int] = set()
    for part in (s or "").split(","):
        p = part.strip()
        if not p:
            continue
        try:
            # Jeśli zaczyna się od 0x/0X -> interpretuj jako hex, inaczej jako dziesiętny
            out.add(int(p, 16) if p.lower().startswith("0x") else int(p, 10))
        except ValueError:
            # Ignoruj niepoprawne wpisy
            pass
    return out


class QosEdgeOnly(QoSTreeController):
    """
    Edge-only QoS:
    - Instaluj QoS wyłącznie na przełącznikach (DPID-ach) wskazanych na whitelist.
    - Tryby:
        * 'htb'   -> użycie kolejek (set_queue),
        * 'meter' -> użycie meterów (meter:<id>).
    """

    # Wersja protokołu OpenFlow
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # DSCP klasy ruchu
    _DSCP_EF = 46    # Expedited Forwarding
    _DSCP_AF31 = 26  # Assured Forwarding klasa AF31
    _DSCP_BE = 0     # Best Effort

    # Mapowanie klas -> queue_id
    _Q_EF = 2
    _Q_AF = 1
    _Q_BE = 0

    def __init__(self, *args, **kwargs):
        """
        Inicjalizacja kontrolera QoS:
        - odczyt trybu QoS,
        - zbudowanie whitelisty DPID-ów,
        - odczyt ID meterów i parametrów przepustowości z ENV.
        """
        super().__init__(*args, **kwargs)

        # Tryb działania QoS: 'none' / 'htb' / 'meter'
        self.qos_mode = _env_flag("QOS_MODE", "none").lower()

        # TYLKO na tych DPID-ach instaluj QoS (np. sp1); pusta lista -> instaluj wszędzie
        self.whitelist: Set[int] = _parse_dpid_list(
            _env_flag("QOS_CLASSIFY_DPIDS", "0xd")
        )

        # Statyczne ID meterów (z ENV lub domyślne wartości)
        self.m_ef = _env_int("QOS_EF_METER_ID", 1)
        self.m_af = _env_int("QOS_AF_METER_ID", 2)
        self.m_be = _env_int("QOS_BE_METER_ID", 3)

        # Stawki z ENV (w MBIT) -> przelicz na kbps (x1000)
        self.ef_kbps = _env_int("QOS_EF_MBIT", 60) * 1000
        self.af_kbps = _env_int("QOS_AF_MBIT", 30) * 1000
        self.be_kbps = _env_int("QOS_BE_MBIT", 10) * 1000

        # Burst z ENV (w MB) -> przelicz na kB (x1024)
        self.ef_burst_kb = _env_int("QOS_EF_BURST_MB", 1) * 1024
        self.af_burst_kb = _env_int("QOS_AF_BURST_MB", 1) * 1024
        self.be_burst_kb = _env_int("QOS_BE_BURST_MB", 2) * 1024

    def _only_this_dp(self, dp_id: int) -> bool:
        """
        Sprawdza, czy na danym DPID powinniśmy instalować QoS:
        - jeżeli whitelist jest pusta -> True (instaluj wszędzie),
        - jeżeli niepusta -> True tylko dla DPID-ów z whitelisty.
        """
        return (not self.whitelist) or (dp_id in self.whitelist)

    def _install_meters(self, dp) -> None:
        """
        Tworzy / odświeża metery EF/AF/BE na podanym datapath (dp):
        - najpierw usuwa istniejące metery o wskazanych ID,
        - następnie tworzy nowe metery z parametrami odczytanymi z ENV.
        """
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # Najpierw usuń istniejące definicje tych meterów (jeżeli są)
        for mid in (self.m_ef, self.m_af, self.m_be):
            dp.send_msg(
                parser.OFPMeterMod(
                    datapath=dp,
                    command=ofp.OFPMC_DELETE,
                    flags=0,
                    meter_id=mid,
                    bands=[]
                )
            )

        # Flagi metera: jednostka kbps + burst
        flags = ofp.OFPMF_KBPS | ofp.OFPMF_BURST

        def add_meter(mid: int, kbps: int, burst_kb: int) -> None:
            """
            Pomocniczo: dodaj pojedynczy meter z pasmem `kbps` i burstem `burst_kb`.
            """
            band = parser.OFPMeterBandDrop(rate=kbps, burst_size=burst_kb)
            mod = parser.OFPMeterMod(
                datapath=dp,
                command=ofp.OFPMC_ADD,
                flags=flags,
                meter_id=mid,
                bands=[band]
            )
            dp.send_msg(mod)

        # Utworzenie meterów dla klas EF/AF/BE
        add_meter(self.m_ef, self.ef_kbps, self.ef_burst_kb)
        add_meter(self.m_af, self.af_kbps, self.af_burst_kb)
        add_meter(self.m_be, self.be_kbps, self.be_burst_kb)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Obsługa zdarzenia OFPSwitchFeatures:
        - najpierw uruchamia logikę bazową L2 (QoSTreeController),
        - następnie, w zależności od trybu, instaluje reguły QoS (meter/htb),
        - działa tylko na przełącznikach, które przejdą filtr `_only_this_dp`.
        """
        # Najpierw baza L2 (instalacja reguł przełączania)
        super().switch_features_handler(ev)

        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # Sprawdź, czy ten DPID jest objęty polityką QoS
        if not self._only_this_dp(dp.id):
            self.logger.info(
                "[QoS/edge-only] pomijam dp=%s (nie jest na whitelist)",
                hex(dp.id),
            )
            return

        mode = self.qos_mode
        if mode not in ("htb", "meter"):
            # Tryb 'none' lub nieznany -> nie instaluj żadnego QoS
            self.logger.info(
                "[QoS/edge-only] mode=%s -> brak QoS na dp=%s",
                mode,
                hex(dp.id),
            )
            return

        # Wysoki priorytet dla reguł klasyfikacji QoS
        prio = 20000
        # Używamy tabeli 0 jako punktu wejścia (potem goto table=1)
        table_id = 0

        if mode == "meter":
            # --- Tryb meter ---
            # 1) zainstaluj definicje meterów
            self._install_meters(dp)

            # 2) klasyfikacja DSCP -> przypisanie do meter:<id> -> goto table 1
            for dscp, mid in (
                (self._DSCP_EF, self.m_ef),
                (self._DSCP_AF31, self.m_af),
                (self._DSCP_BE, self.m_be),
            ):
                # Match na ruch IPv4 z danym DSCP
                match = parser.OFPMatch(eth_type=0x0800, ip_dscp=dscp)
                inst = [
                    parser.OFPInstructionMeter(mid),
                    parser.OFPInstructionGotoTable(1),
                ]
                dp.send_msg(
                    parser.OFPFlowMod(
                        datapath=dp,
                        table_id=table_id,
                        priority=prio,
                        match=match,
                        instructions=inst,
                    )
                )

            self.logger.info(
                "[QoS/meter] zainstalowano metery+reguły na dp=%s | "
                "EF=%dkbps AF=%dkbps BE=%dkbps",
                hex(dp.id),
                self.ef_kbps,
                self.af_kbps,
                self.be_kbps,
            )

        elif mode == "htb":
            # --- Tryb HTB (kolejki) ---
            # DSCP -> set_queue -> goto table 1
            for dscp, qid in (
                (self._DSCP_EF, self._Q_EF),
                (self._DSCP_AF31, self._Q_AF),
                (self._DSCP_BE, self._Q_BE),
            ):
                match = parser.OFPMatch(eth_type=0x0800, ip_dscp=dscp)
                inst = [
                    parser.OFPInstructionActions(
                        ofp.OFPIT_WRITE_ACTIONS,
                        [parser.OFPActionSetQueue(qid)],
                    ),
                    parser.OFPInstructionGotoTable(1),
                ]
                dp.send_msg(
                    parser.OFPFlowMod(
                        datapath=dp,
                        table_id=table_id,
                        priority=prio,
                        match=match,
                        instructions=inst,
                    )
                )

            self.logger.info(
                "[QoS/htb] zainstalowano reguły set_queue na dp=%s",
                hex(dp.id),
            )


def main() -> None:
    """
    Punkt wejścia – uruchamia aplikację Ryu z kontrolerem QosEdgeOnly.
    """
    app_manager.AppManager.run_apps(['ryu_qos_edge.QosEdgeOnly'])


if __name__ == "__main__":
    main()
