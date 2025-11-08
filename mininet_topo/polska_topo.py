from mininet.topo import Topo
from mininet.link import TCLink
from mininet.node import OVSSwitch

# Lista miast → stałe DPIDy (kolejność ma znaczenie)
CITIES = [
    "Gdansk",
    "Bydgoszcz",
    "Kolobrzeg",
    "Katowice",
    "Krakow",
    "Bialystok",
    "Lodz",
    "Poznan",
    "Rzeszow",
    "Szczecin",
    "Warsaw",
    "Wroclaw",
]

# Nieskierowane łącza rdzeniowe (core)
LINKS = [
    ("Gdansk", "Warsaw"),
    ("Gdansk", "Kolobrzeg"),
    ("Bydgoszcz", "Kolobrzeg"),
    ("Bydgoszcz", "Poznan"),
    ("Bydgoszcz", "Warsaw"),
    ("Kolobrzeg", "Szczecin"),
    ("Katowice", "Krakow"),
    ("Katowice", "Lodz"),
    ("Katowice", "Wroclaw"),
    ("Krakow", "Rzeszow"),
    ("Krakow", "Warsaw"),
    ("Bialystok", "Rzeszow"),
    ("Bialystok", "Warsaw"),
    ("Lodz", "Warsaw"),
    ("Lodz", "Wroclaw"),
    ("Poznan", "Szczecin"),
    ("Poznan", "Wroclaw"),
    ("Gdansk", "Bialystok"),
]

# Domyślne parametry łączy (rdzeń + uplinki providerów)
DEFAULT_BW = 100        # Mbit/s
DEFAULT_DELAY = "5ms"
DEFAULT_JITTER = "1ms"
DEFAULT_LOSS = 0.1      # %

# Miejsca, w których provider „wchodzi” do rdzenia
HOST_EDGE = {
    "h1": "Gdansk",
    "h2": "Krakow",
}


def dpid_for(idx: int) -> str:
    """Zwraca DPID jako 16-znakowy string heksadecymalny."""
    return f"{idx:016x}"


class PolskaTopoShort(Topo):
    """
    - Rdzeń: switche s1..s12 (każdy odpowiada miastu z CITIES),
      połączone łączami z TBF + netem (use_tbf=True).
    - Provider-edge: sp1 (przy h1) i sp2 (przy h2).
    """

    def build(self, bw: int = DEFAULT_BW, delay: str = DEFAULT_DELAY):
        # Mapowanie nazwa miasta -> switch rdzeniowy
        city_to_sw = {}

        # 1) Switche rdzeniowe s1..s12 (z ustalonymi DPIDami)
        for idx, city in enumerate(CITIES, start=1):
            sw = self.addSwitch(
                f"s{idx}",
                cls=OVSSwitch,
                protocols="OpenFlow13",
                dpid=dpid_for(idx),
            )
            city_to_sw[city] = sw

        # 2) Łącza rdzeniowe: TBF + emulacja opóźnień/strat (netem)
        for a, b in LINKS:
            self.addLink(
                city_to_sw[a],
                city_to_sw[b],
                cls=TCLink,
                bw=bw,
                delay=delay,
                jitter=DEFAULT_JITTER,
                loss=DEFAULT_LOSS,
                use_tbf=True,
            )

        # 3) Switche providerskie z unikalnymi DPID (poza zakresem rdzenia)
        sp1_idx = len(CITIES) + 1
        sp2_idx = len(CITIES) + 2

        sp1 = self.addSwitch(
            "sp1",
            cls=OVSSwitch,
            protocols="OpenFlow13",
            dpid=dpid_for(sp1_idx),
        )
        sp2 = self.addSwitch(
            "sp2",
            cls=OVSSwitch,
            protocols="OpenFlow13",
            dpid=dpid_for(sp2_idx),
        )

        # 4) Hosty końcowe podłączone do providerów (bez ograniczeń TC)
        h1 = self.addHost("h1")
        h2 = self.addHost("h2")

        self.addLink(h1, sp1)
        self.addLink(h2, sp2)

        # 5) Uplinki provider -> rdzeń (TBF + netem)
        #    Pierwszy „rdzeniowy” skok dla h1 i h2.
        self.addLink(
            sp1,
            city_to_sw[HOST_EDGE["h1"]],
            cls=TCLink,
            bw=bw,
            delay=delay,
            jitter=DEFAULT_JITTER,
            loss=DEFAULT_LOSS,
            use_tbf=True,
        )
        self.addLink(
            sp2,
            city_to_sw[HOST_EDGE["h2"]],
            cls=TCLink,
            bw=bw,
            delay=delay,
            jitter=DEFAULT_JITTER,
            loss=DEFAULT_LOSS,
            use_tbf=True,
        )


# Rejestracja topologii dla `mn --custom`
topos = {
    "polska": PolskaTopoShort,
    "mytopo": PolskaTopoShort,
}
