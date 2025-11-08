from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet
from ryu.lib.packet import ether_types

from ryu_base import QoSTreeBase


class QoSTreeController(QoSTreeBase):
    """
    Kontroler L2 oparty o QoSTreeBase:
      - obsługa PACKET_IN,
      - nauka adresów MAC (MAC learning),
      - globalny flood ARP na porty hostów,
      - ograniczony flood (limited flood) w oparciu o:
          * porty hostów (host_ports),
          * porty z drzewa rozpinającego (sp_tree).
    """

    # ========= L2 / flooding / packet-in handling =========

    def _arp_host_flood_global(self, in_dp, in_port: int, data: bytes) -> None:
        """
        Wysyła ARP (data) do wszystkich portów hostów we wszystkich datapathach,
        z pominięciem portu wejściowego (in_dp, in_port).

        - in_dp: datapath, na którym przyszedł ARP,
        - in_port: port wejściowy na in_dp,
        - data: surowe dane pakietu z msg.data.
        """
        ofp = in_dp.ofproto
        p = in_dp.ofproto_parser

        self.logger.info(
            "[ARP-FLOOD] in_dpid=%s in_port=%s host_ports_snapshot=%s",
            hex(in_dp.id),
            in_port,
            {hex(d): sorted(list(ps)) for d, ps in self.host_ports.items()},
        )

        total_sent = 0

        # Przechodzimy po znanych datapathach
        for dpid, dp in list(self.datapaths.items()):
            ports = sorted(self.host_ports.get(dpid, set()))
            if not ports:
                self.logger.debug(
                    "[ARP-FLOOD] skipping dpid=%s (no host ports)",
                    hex(dpid),
                )
                continue

            # Flood po portach hostów (z pominięciem portu wejściowego)
            for port in ports:
                if dpid == in_dp.id and port == in_port:
                    self.logger.debug(
                        "[ARP-FLOOD] skip ingress port dpid=%s port=%s",
                        hex(dpid),
                        port,
                    )
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
                    self.logger.debug(
                        "[ARP-FLOOD] pktout -> dpid=%s port=%s",
                        hex(dpid),
                        port,
                    )
                except Exception as e:
                    self.logger.exception(
                        "[ARP-FLOOD] error sending pktout to dpid=%s port=%s: %s",
                        hex(dpid),
                        port,
                        e,
                    )

        self.logger.info(
            "[ARP-FLOOD] finished, total pktouts sent=%d",
            total_sent,
        )

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Główna obsługa PACKET_IN:
          - filtruje LLDP,
          - uczy MAC (mac_to_port + host_ports),
          - ARP: globalny flood na porty hostów,
          - unicast: instalacja flow w T1 i OFPPacketOut,
          - inaczej: limited flood (host_ports + sp_tree).
        """
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        p = dp.ofproto_parser

        dpid = dp.id
        in_port = msg.match.get("in_port")

        # Parsowanie nagłówków
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            self.logger.debug("[PKT-IN] no ethernet header, ignoring")
            return

        src = eth.src
        dst = eth.dst
        eth_type = eth.ethertype

        self.logger.debug(
            "[PKT-IN] dpid=%s in_port=%s eth_type=0x%04x src=%s dst=%s pkt_len=%d",
            hex(dpid),
            in_port,
            eth_type,
            src,
            dst,
            len(msg.data),
        )

        # LLDP już dropowany w T0, tutaj tylko dodatkowa osłona
        if eth_type == ether_types.ETH_TYPE_LLDP:
            self.logger.debug(
                "[PKT-IN] LLDP received on dpid=%s port=%s -> ignored (LLDP)",
                hex(dpid),
                in_port,
            )
            return

        # Snapshot stanu (debug)
        self.logger.debug(
            "[STATE] datapaths=%s",
            [hex(k) for k in self.datapaths.keys()],
        )
        self.logger.debug(
            "[STATE] graph=%s",
            {hex(k): {hex(u): v for u, v in vs.items()} for k, vs in self.graph.items()},
        )
        self.logger.debug(
            "[STATE] sp_tree=%s",
            {hex(k): sorted(list(v)) for k, v in self.sp_tree.items()},
        )
        self.logger.debug(
            "[STATE] host_ports=%s",
            {hex(k): sorted(list(v)) for k, v in self.host_ports.items()},
        )

        # Nauka źródłowego MAC-a + kwalifikacja portu jako hostowego
        prev = self.mac_to_port.get(dpid, {}).get(src)
        self.mac_to_port.setdefault(dpid, {})[src] = in_port

        if prev is None:
            self.logger.info(
                "[LEARN] dpid=%s learned src=%s -> port=%s",
                hex(dpid),
                src,
                in_port,
            )
        elif prev != in_port:
            self.logger.info(
                "[LEARN] dpid=%s updated src=%s port %s -> %s",
                hex(dpid),
                src,
                prev,
                in_port,
            )

        # Sprawdzamy, czy in_port jest portem łączącym switche (link-port)
        is_link_port = any(
            u_p == in_port
            for _, (u_p, v_p) in self.graph.get(dpid, {}).items()
        )
        self.logger.debug(
            "[PORT-TYPE] dpid=%s in_port=%s is_link_port=%s",
            hex(dpid),
            in_port,
            is_link_port,
        )

        # Jeśli to nie jest port linkowy, traktujemy go jako port hosta
        if not is_link_port:
            self.host_ports.setdefault(dpid, set()).add(in_port)
            self.logger.debug(
                "[HOST-PORT] added dpid=%s port=%s to host_ports",
                hex(dpid),
                in_port,
            )

        # ARP -> globalny flood na porty hostów
        if eth_type == ether_types.ETH_TYPE_ARP:
            self.logger.info(
                "[PKT-IN-ARP] dpid=%s in_port=%s src=%s dst=%s => ARP flood global",
                hex(dpid),
                in_port,
                src,
                dst,
            )
            self._arp_host_flood_global(dp, in_port, msg.data)
            return

        # Unicast (jeśli znamy port docelowy dla dst na tym dpid)
        if dst in self.mac_to_port.get(dpid, {}):
            out_port = self.mac_to_port[dpid][dst]
            self.logger.info(
                "[UNICAST] dpid=%s dst=%s known -> out_port=%s (installing flow)",
                hex(dpid),
                dst,
                out_port,
            )

            # Flow w T1: dopasowanie po MAC docelowym
            match = p.OFPMatch(eth_dst=dst)
            actions = [p.OFPActionOutput(out_port)]
            inst = [p.OFPInstructionActions(ofp.OFPIT_WRITE_ACTIONS, actions)]

            # Instalujemy flow
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
                self.logger.debug(
                    "[FLOWMOD] dpid=%s installed L2 unicast flow dst=%s -> out=%s",
                    hex(dpid),
                    dst,
                    out_port,
                )
            except Exception as e:
                self.logger.exception(
                    "[FLOWMOD] error installing flow on dpid=%s dst=%s: %s",
                    hex(dpid),
                    dst,
                    e,
                )

            # I wysyłamy bieżący pakiet jako pkt-out
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
                self.logger.debug(
                    "[PKT-OUT] unicast pktout sent dpid=%s -> port=%s dst=%s",
                    hex(dpid),
                    out_port,
                    dst,
                )
            except Exception as e:
                self.logger.exception(
                    "[PKT-OUT] error sending unicast pktout on dpid=%s: %s",
                    hex(dpid),
                    e,
                )
            return

        # Brak MAC-a docelowego w tabeli -> ograniczony flood:
        #   host_ports (bez portu wejściowego) + porty z drzewa rozpinającego
        actions = []
        actions_ports = []

        # Porty hostów na tym dpid
        for port in sorted(self.host_ports.get(dpid, set())):
            if port != in_port:
                actions.append(p.OFPActionOutput(port))
                actions_ports.append(port)

        # Porty z drzewa rozpinającego na tym dpid
        for port in sorted(self.sp_tree.get(dpid, set())):
            if port != in_port:
                actions.append(p.OFPActionOutput(port))
                actions_ports.append(port)

        if not actions:
            self.logger.info(
                "[LIMITED-FLOOD] dpid=%s in_port=%s -> no actions built (host_ports=%s sp_tree=%s).",
                hex(dpid),
                in_port,
                sorted(self.host_ports.get(dpid, set())),
                sorted(self.sp_tree.get(dpid, set())),
            )
        else:
            self.logger.info(
                "[LIMITED-FLOOD] dpid=%s in_port=%s actions_ports=%s dst=%s",
                hex(dpid),
                in_port,
                actions_ports,
                dst,
            )

        # Jeśli mamy jakieś akcje floodowania – odsyłamy pakiet
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
                self.logger.debug(
                    "[PKT-OUT] flood pktout sent dpid=%s in_port=%s -> ports=%s",
                    hex(dpid),
                    in_port,
                    actions_ports,
                )
            except Exception as e:
                self.logger.exception(
                    "[PKT-OUT] error sending flood pktout on dpid=%s: %s",
                    hex(dpid),
                    e,
                )
