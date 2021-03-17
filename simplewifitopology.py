#!/usr/bin/python

'This example creates a simple network topology with 1 AP and 2 stations'

import sys

from mininet.log import setLogLevel, info
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi


def topology():
    "Create a network."
    net = Mininet_wifi()

    info("*** Creating nodes\n")
    sta_arg = dict()
    ap_arg = dict()


    s0 = net.addSwitch('s0')
    ap1 = net.addAccessPoint('ap1', ssid='ssid_ap1', mode='a', channel='36',
                             position='10,30,0', range='20')

    ap3 = net.addAccessPoint('ap3', ssid="ssid_ap3", mode="g", channel="10",
                             position='50,30,0', range='20')

    sta1 = net.addStation('sta1', mac='AA:BB:BB:BB:BB:01',
                           defaultRoute='via 192.168.0.224',
                           ip='192.168.0.11/240',
                           position='10,40,0')

    sta2 = net.addStation('sta2', mac='AA:BB:BB:BB:BB:02',
                           defaultRoute='via 192.168.0.224',
                           ip='192.168.0.12/24',
                           position='15,30,0')

    sta3 = net.addStation('sta3', mac='AA:BB:BB:BB:BB:03',
                           defaultRoute='via 192.168.0.224',
                           ip='192.168.0.13/24',
                           position='15,35,0')

    sta4 = net.addStation('sta4', mac='AA:BB:BB:BB:BB:11',
                           defaultRoute='via 10.0.0.22',
                           ip='10.0.0.1/24',
                           position='50,20,0')

    sta5 = net.addStation('sta5', mac='AA:BB:BB:BB:BB:12',
                           defaultRoute='via 10.0.0.22',
                           ip='10.0.0.22/24',
                           position='55,15,0')

    sta6 = net.addStation('sta6', mac='AA:BB:BB:BB:BB:13',
                           defaultRoute='via 10.0.0.22', 
                           ip='10.0.0.3/24',
                           position='45,125,0')

    h1 = net.addHost('h1', ip='192.168.0.1', mac='AA:AA:AA:AA:AA:01',
                     defaultRoute='via 192.168.0.224')
    h2 = net.addHost('h2', ip='192.168.0.2', mac='AA:AA:AA:AA:AA:02',
                     defaultRoute='via 192.168.0.224')
    h3 = net.addHost('h3', ip='192.168.0.3', mac='AA:AA:AA:AA:AA:03',
                     defaultRoute='via 192.168.0.224')
    h4 = net.addHost('h4', ip='192.168.0.4', mac='AA:AA:AA:AA:AA:04',
                     defaultRoute='via 192.168.0.224')
    h5 = net.addHost('h5', ip='192.168.0.5', mac='AA:AA:AA:AA:AA:05',
                     defaultRoute='via 192.168.0.224')
    h6 = net.addHost('h6', ip='192.168.0.6', mac='AA:AA:AA:AA:AA:06',
                     defaultRoute='via 192.168.0.224')


#    ap1 = net.addAccessPoint('ap1', ssid="simpletopo", mode="g",
#                             channel="5", **ap_arg)
#    sta1 = net.addStation('sta1', **sta_arg)
#    sta2 = net.addStation('sta2')
    c0 = net.addController('c0')

   #####################   Link devices to Switch    ######################
    net.addLink(ap1, s0)
    net.addLink(h1, s0)
    net.addLink(h2, s0)
    net.addLink(h3, s0)
    net.addLink(h4, s0)
    net.addLink(h5, s0)
    net.addLink(h6, s0)


    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

#    info("*** Associating Stations\n")
#    net.addLink(sta1, ap1)
#    net.addLink(sta2, ap1)

    ################   Wireless AP Interface   ##########################
    print ("*** Adding Link")
    net.addLink(ap1, sta1)
    net.addLink(sta2, ap1, bw=10, loss=5)
    net.addLink(sta3, ap1, bw=10, loss=5)

    info("*** Starting network\n")
    net.build()
    c0.start()
    ap1.start([c0])

    if '-v' not in sys.argv:
        ap1.cmd('ovs-ofctl add-flow ap1 "priority=0,arp,in_port=1,'
                'actions=output:in_port,normal"')
        ap1.cmd('ovs-ofctl add-flow ap1 "priority=0,icmp,in_port=1,'
                'actions=output:in_port,normal"')
        ap1.cmd('ovs-ofctl add-flow ap1 "priority=0,udp,in_port=1,'
                'actions=output:in_port,normal"')
        ap1.cmd('ovs-ofctl add-flow ap1 "priority=0,tcp,in_port=1,'
                'actions=output:in_port,normal"')

    info("*** Running CLI\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology()
