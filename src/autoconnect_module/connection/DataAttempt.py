from connection.HeuristicAttempt import HeuristicAttempt
from util.RARPTable import *
from scapy.all import *
from ipaddress import *
from scapy.layers.inet import IP, TCP, Ether
from scapy.layers.l2 import ARP


class DataAttempt(HeuristicAttempt):
    """
    A class used to represent a Heuristic Connection Attempt that uses broadcast traffic and data traffic,
    in particular ARP traffic and TCP traffic.

    Attributes
    ----------
    rarp_table : RARPTable
        a Reverse ARP Table
    packets : PacketList
        list of sniffed packets
    gateway_mac : str
        gateway MAC address

    Methods
    -------
    connect()
        Tries to discover connection settings analyzing ARP and TCP data traffic and applying heuristics
    find_gateway()
        Returns the gateway IP address, that is the IP whose MAC contains more IPs in the RARP Table
    find_ip()
        Returns a free IP address, that is the first IP address in the subnet that does not send an ARP Reply
    network_discover()
        Finds the network address and the subnet mask after discovering the gateway considering:
            - source and destination IP addresses of ARP packets
            - destination IP address of TCP data packets whose source MAC address is the MAC address of the gateway
            - source IP address of TCP data packets whose destination MAC address is the MAC address of the gateway
    find_gateway_ip()
        Given the gateway MAC address it returns the gateway IP address, that is the IP marked as seen in ARP packet in the RARPTable entry
    arp_process()
        Adds the source IP address and the destination IP address of the ARP packet in the RARP Table
    tcp_process()
        Adds the source IP address and the destination IP address of the TCP packet in the RARP Table

    """

    def __init__(self, interface):
        HeuristicAttempt.__init__(self, interface)
        self.rarp_table = RARPTable()
        self.packets = None
        self.gateway_mac = None

    def connect(self):
        """
        Tries to discover connection settings analyzing ARP and TCP data traffic and applying heuristics.
        The IP address of the gateway is the IP whose MAC contains more IPs in the RARP Table.
        That is, the MAC address associated with more IP addresses.
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
        self.rarp_table.print()
        self.gateway = IPv4Address(self.find_gateway())
        self.network = IPv4Network(self.network_discover())
        print("Network: " + str(self.network))
        logging.info("Network: " + str(self.network))
        print("Default gateway: " + str(self.gateway))
        logging.info("Default gateway: " + str(self.gateway))
        self.ip = IPv4Address(self.find_ip())
        print("IP address: " + str(self.ip))
        logging.info("IP address: " + str(self.ip))

        return self.configure_network()

    def find_gateway(self):
        """
        Returns the gateway IP address, that is the IP whose MAC contains more IPs in the RARP Table.

        Returns
        -------
        str
            gateway IP address
        """
        max_count = 0
        max_mac = None
        for mac in self.rarp_table.table:
            size = len(self.rarp_table.table[mac])
            if size >= max_count:
                max_count = size
                max_mac = mac
        if max_mac is not None:
            self.gateway_mac = max_mac
            return self.find_gateway_ip(max_mac)

    def network_discover(self):
        """
        Finds the network address and the subnet mask after discovering the gateway considering:
            - source and destination IP addresses of ARP packets
            - destination IP address of TCP data packets whose source MAC address is the MAC address of the gateway
            - source IP address of TCP data packets whose destination MAC address is the MAC address of the gateway

        For every IP it calls the add_ip function and finally it calls the find_network function.

        Returns
        -------
        str
            a string obtained concatenating the network address and the subnet mask. Ex: 192.168.0.0/24

        """
        for pkt in self.packets:
            if ARP in pkt:
                ip_src = pkt[ARP].psrc
                if ip_src not in self.ignore_ip:
                    self.add_ip(ip_src)
                ip_dst = pkt[ARP].pdst
                if ip_dst not in self.ignore_ip:
                    self.add_ip(ip_dst)
            elif TCP in pkt:
                mac_src = pkt[Ether].src
                mac_dst = pkt[Ether].dst
                if mac_src == self.gateway_mac:
                    ip_dst = pkt[IP].dst
                    self.add_ip(ip_dst)
                elif mac_dst == self.gateway_mac:
                    ip_src = pkt[IP].src
                    self.add_ip(ip_src)

        return self.find_network()

    def find_gateway_ip(self, max_mac):
        """
        Given the gateway MAC address it returns the gateway IP address, that is the IP marked as seen in ARP packet in the RARPTable entry

        Parameters
        ---------
        max_mac : str
            gateway MAC address

        Returns
        -------
        str
            gateway IP address
        """
        for entry in self.rarp_table.table[max_mac]:
            if entry.in_arp:
                return entry.ip_address

    def sniff(self):
        """
        Calls scapy sniff function to sniff ARP and TCP packets.
        """
        # Every new packet calls the pkt_process function.
        self.packets = sniff(filter="arp || tcp", prn=self.pkt_process, count=100)

    def pkt_process(self, pkt):
        if ARP in pkt:
            self.arp_process(pkt)
        elif TCP in pkt:
            self.tcp_process(pkt)

    def arp_process(self, pkt):
        """
        Adds the source IP address and the destination IP address of the ARP packet in the RARP Table

        Parameters
        ---------
        pkt : Packet
            a new scapy ARP packet
        """
        ip_src = pkt[ARP].psrc
        mac_src = pkt[ARP].hwsrc
        if ip_src not in self.ignore_ip:
            self.rarp_table.add_or_update_entry(mac_src, ip_src, True)
        ip_dst = pkt[ARP].pdst
        mac_dst = pkt[ARP].hwdst
        if ip_dst not in self.ignore_ip:
            self.rarp_table.add_or_update_entry(mac_dst, ip_dst, True)

    def tcp_process(self, pkt):
        """
        Adds the source IP address and the destination IP address of the TCP packet in the RARP Table

        Parameters
        ---------
        pkt : Packet
            a new scapy TCP packet
        """
        ip_src = pkt[IP].src
        mac_src = pkt[Ether].src
        self.rarp_table.add_or_update_entry(mac_src, ip_src, False)
        ip_dst = pkt[IP].dst
        mac_dst = pkt[Ether].dst
        self.rarp_table.add_or_update_entry(mac_dst, ip_dst, False)
