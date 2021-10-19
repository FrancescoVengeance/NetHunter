from scapy.all import *
from connection.HeuristicAttempt import HeuristicAttempt
from util.ARPTable import *
from ipaddress import *
from scapy.layers.l2 import ARP


class BroadcastAttempt(HeuristicAttempt):
    """
    A class used to represent a Heuristic Connection Attempt that uses broadcast traffic, in particular ARP traffic.

    Attributes
    ----------
    arp_table : ARPTable
        an ARPTable object for counting number of occurrences of every IP address in ARP packets
    count : int
        the number of new packets since the network address or the gateway address changed


    Methods
    -------
    connect()
        Tries to discover connection settings analyzing ARP traffic and applying heuristics.
    find_gateway()
        Returns the gateway IP address, that is the IP address with most occurrences in the ARPTable.
    find_ip()
        Returns a free IP address, that is the first IP address in the subnet that does not send an ARP Reply.
    stop_filter()
        Decides when to stop the discovery process.
    sniff()
        Calls scapy sniff function to sniff ARP packets.
    arp_process()
        Adds the source IP address and the destination IP address of the ARP packet in the ARP Table
        or updates the existing table entry incrementing the number of occurrences.
        For the two IPs it calls the add_ip function.

    """

    def __init__(self, interface):
        HeuristicAttempt.__init__(self, interface)
        self.arp_table = ARPTable()
        self.count = 0

    def connect(self):
        """
        Tries to discover connection settings analyzing ARP traffic and applying heuristics.
        The IP address of the gateway is the IP with most occurrences in the ARPTable.
        The network address is determined by doing a bit by bit AND operation (&) on the two values: acc_and & acc_or.
        The subnet mask is determined by doing a bit by bit XOR(exclusive-OR) operation (^) on the two values: acc_and ^ acc_or.
        A free IP address is founded using ARP Requests. The first IP, that does not send an ARP Reply, is selected.
        The process stops when after receiving 20 new packets the network address and the gateway address did not change.

        Returns
        -------
        bool
            returns True if it is able to discover all the connection settings
            returns False otherwise
        """
        self.sniff()
        self.arp_table.print()
        self.network = IPv4Network(self.network)
        self.gateway = IPv4Address(self.gateway)
        print("Network: " + str(self.network))
        logging.info("Network: " + str(self.network))
        print("Default gateway: " + str(self.gateway))
        logging.info("Default gateway: " + str(self.gateway))
        self.ip = IPv4Address(self.find_ip())
        print("IP address: " + str(self.ip))
        logging.info("IP address: " + str(self.ip))

        # Setup the interface
        return self.configure_network()

    def find_gateway(self):
        """
        Returns the gateway IP address, that is the IP address with most occurrences in the ARPTable.

        Returns
        -------
        str
            gateway IP address
        """
        max_count = 0
        gateway = None
        for entry in self.arp_table.table:
            if self.arp_table.table[entry].count > max_count:
                max_count = self.arp_table.table[entry].count
                gateway = self.arp_table.table[entry].ip_address

        return gateway

    def stop_filter(self, x):
        """
        Decides when to stop the discovery process.
        The process stops when after receiving 20 new packets the network address and the gateway address did not change.

        Returns
        -------
        bool
            returns True if after receiving 20 new packets the network address and the gateway address did not change.
            returns False otherwise
        """
        network = self.find_network()
        gateway = self.find_gateway()
        if network != self.network or gateway != self.gateway:
            self.network = network
            self.gateway = gateway
            self.count = 1
        else:
            self.count += 1

        if self.count == 20:
            return True
        else:
            return False

    def sniff(self):
        """
        Calls scapy sniff function to sniff ARP packets.
        """
        # Every new packet calls the arp_process function.
        # The function stop_filter is called every time a new packet arrives to decide if the sniff function must stop.
        sniff(filter="arp", prn=self.arp_process, stop_filter=self.stop_filter, store=0)

    def arp_process(self, pkt):
        """
        Adds the source IP address and the destination IP address of the ARP packet in the ARP Table
        or updates the existing table entry incrementing the number of occurrences.
        For the two IPs it calls the add_ip function.

        Parameters
        ---------
        pkt : Packet
            a new scapy ARP packet
        """
        ip_src = pkt[ARP].psrc
        mac_src = pkt[ARP].hwsrc
        if ip_src not in self.ignore_ip:
            self.arp_table.add_or_update_entry(ip_src, mac_src)
            self.add_ip(ip_src)
        ip_dst = pkt[ARP].pdst
        mac_dst = pkt[ARP].hwdst
        if ip_dst not in self.ignore_ip:
            self.arp_table.add_or_update_entry(ip_dst, mac_dst)
            self.add_ip(ip_dst)
