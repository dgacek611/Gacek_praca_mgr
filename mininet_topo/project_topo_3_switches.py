from mininet.topo import Topo

class MyTopo(Topo):
    def __init__(self):
        Topo.__init__(self)
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        # Access (szerokie) – bez bw/use_htb (zero warningów); delay opcjonalny
        self.addLink(h1, s1, delay='1ms')
        self.addLink(s2, h2, delay='1ms')

        # Rdzeń – szeroki (bez rate), alternatywna ścieżka
        self.addLink(s1, s2, delay='5ms')
        self.addLink(s1, s3, delay='5ms')
        self.addLink(s3, s2, delay='5ms')

topos = {'mytopo': (lambda: MyTopo())}