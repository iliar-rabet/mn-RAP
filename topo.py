#!/usr/bin/python

"Setting the position of Nodes with wmediumd to calculate the interference"

import sys

from mininet.log import setLogLevel, info
from mn_wifi.link import wmediumd
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi
from mn_wifi.wmediumdConnector import interference
from mininet.net import Mininet
from mininet.node import  Controller, OVSKernelSwitch, RemoteController
from mininet.node import OVSSwitch, UserSwitch
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from mininet.nodelib import NAT
from mininet.topo import Topo

def topology(args):
    "Create a network."
    net = Mininet_wifi(link=wmediumd, wmediumd_mode=interference,
                       noise_th=-91, fading_cof=3)
    c0 = Controller( 'c0', port=6634 )
    net.addController(c0)
    #create controller for s0 (Ryuretic)

    info("*** Creating nodes\n")
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

   #####################   Link devices to Switch    ######################
    net.addLink(ap1, s0)
    net.addLink(h1, s0)
    net.addLink(h2, s0)
    net.addLink(h3, s0)
    net.addLink(h4, s0)
    net.addLink(h5, s0)
    net.addLink(h6, s0)

    ################   Wireless AP Interface   ##########################
 #   print ("*** Adding Link")
#    net.addLink(ap1, sta1)
 #   net.addLink(sta2, ap1, bw=10, loss=5)
#    net.addLink(sta3, ap1, bw=10, loss=5)


    info("*** Configuring Propagation Model\n")
    net.setPropagationModel(model="logDistance", exp=4)

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

    if '-p' not in args:
        net.plotGraph(max_x=100, max_y=100)

   #########################   Build Topology      #########################
    net.build()
   ######################   Start Topology      ########################
    info("*** Starting network\n")
    c0.start()
    ap1.start([c0])
    ap3.start([c0])
    s0.start([c0])
    info("*** Running CLI\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology(sys.argv)
