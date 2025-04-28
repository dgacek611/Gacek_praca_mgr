from mininet.topo import Topo

class MyTopo(Topo):
    "Topology used in the project."
    
    def __init__(self):
        "Create custom topo."
        # Initialize topology
        Topo.__init__(self)
        
        # Add hosts and switches
        leftHost = self.addHost('h1')
        rightHost = self.addHost('h2')
        leftSwitch = self.addSwitch('s1')
        rightSwitch = self.addSwitch('s2')
        additionalSwitch = self.addSwitch('s3')
        
        # Add links
        self.addLink(leftHost, leftSwitch)
        self.addLink(leftSwitch, rightSwitch)
        self.addLink(rightSwitch, rightHost)
        self.addLink(leftSwitch, additionalSwitch)
        self.addLink(additionalSwitch, rightSwitch)

topos = {'mytopo': (lambda: MyTopo())}
