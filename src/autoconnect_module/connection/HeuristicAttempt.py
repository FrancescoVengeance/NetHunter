from abc import abstractmethod
from connection.ConnectionAttempt import ConnectionAttempt
from ipaddress import *
from scapy.all import *
from scapy.layers.inet import Ether
from scapy.layers.l2 import ARP
from util.Interface import *


class HeuristicAttempt (ConnectionAttempt):
    """
    An abstract class used to represent an Heuristic Connection Attempt

    Attributes
    ----------
    interface : str
        the name of the interface to connect
    acc_and : int
        an accumulator used to determine the network address and the subnet mask.
        It can be seen as a lower bound of the ip addresses in the network
    acc_or : int
        an accumulator used to determine the network address and the subnet mask.
        It can be seen as an upper bound of the ip addresses in the network
    network : IPv4Network
        an IPv4Network object used to represent the Network
    gateway : IPv4Address
        an IPv4Address object used to represent the IP address of the gateway
    ip : IPv4Address
        an IPv4Address object used to represent a free IP address that will be used
    ignore_ip : Set[str]
        set of IP address to ignore during the process of the packets

    Methods
    -------
    find_network()
        Finds the network address and the subnet mask analyzing network traffic
    find_gateway()
        Finds the gateway analyzing network traffic
    find_ip()
        Finds a free IP address through ARP Requests
    add_ip(ip_addr)
        Adds the IP address that comes from a new packet in the two accumulators (acc_and, acc_or).
    check_ip(ip_addr)
        Checks if the IP address is in the subnet through an ARP REQUEST to avoid processing IP of a different subnet
    make_arp_request(ip_src, ip_dst)
        Creates an ARP REQUEST packet
    connect()
        Tries to discover connection settings analyzing network traffic and applying heuristics
    configure_network()
        Configures the interface with the connection settings: network, gateway, IP address

    """

    def __init__(self, interface):
        ConnectionAttempt.__init__(self, interface)
        self.acc_and = 0xffffffff   # 11111111 11111111 11111111 11111111
        self.acc_or = 0x00000000    # 00000000 00000000 00000000 00000000
        self.network = None
        self.gateway = None
        self.ip = None
        self.ignore_ip = {'0.0.0.0', '255.255.255.255'}

    def find_network(self):
        """
        Finds the network address and the subnet mask analyzing network traffic
        The network address is determined by doing a bit by bit AND operation (&) on the two values: acc_and & acc_or.
        The subnet mask is determined by doing a bit by bit XOR(exclusive-OR) operation (^) on the two values: acc_and ^ acc_or.

        Returns
        -------
        str
            a string obtained concatenating the network address and the subnet mask. Ex: 192.168.0.0/24

        """
        # TODO Fix subnet_mask in case of ones after the first zero.
        net_address = self.acc_and & self.acc_or
        subnet_mask = self.acc_and ^ self.acc_or
        # print("SUBNET: " + hex(net_address) + "\t" + hex(subnet_mask))

        # Convert wildcard to subnet mask
        subnet_mask = 0xffffffff - subnet_mask

        net_address_str = str(IPv4Address(net_address))
        net_address_str += "/" + str(IPv4Address(subnet_mask))

        return net_address_str

    @abstractmethod
    def find_gateway(self):
        """
        Finds the gateway analyzing network traffic

        Returns
        -------
        str
            IP Address of the gateway
        """
        pass

    def find_ip(self):
        """
        Returns a free IP address, that is the first IP address in the subnet that does not send an ARP Reply to the ARP Probe.

        Returns
        -------
        str
            free IP Address
        """
        hosts = list(self.network.hosts())
        for ip in hosts:
            ip_dst = str(ip)
            if not self.check_ip(ip_dst):
                return ip

    def add_ip(self, ip_addr):
        """
        Adds the IP address that comes from a new packet in the two accumulators (acc_and, acc_or).
        The network portion of the address should stay the same in both (after the first operation),
        but in acc_and the bottom bits should start clearing out while in the acc_or the bottom bits should start filling up

        Parameters
        ----------
        ip_addr : str
            an IP address that is present in a new packet

        """
        # arp_reply = self.check_ip(ip_addr)
        # if arp_reply:
        #     print("Adding IP: " + ip_addr)
        ip = int(IPv4Address(ip_addr))
        self.acc_and &= ip
        self.acc_or |= ip
        # print(ip_addr + "\t" + hex(ip))
        # print(hex(self.acc_and) + "\t" + hex(self.acc_or) + "\n", end='')
        # print(str(IPv4Address(self.acc_and)) + "\t" + str(IPv4Address(self.acc_or)) + "\n", end='')

    def check_ip(self, ip_addr):
        """
        Checks if the IP address is in the subnet through ARP PROBE to avoid processing IP of a different subnet

        Parameters
        ----------
        ip_addr : str
            IP address to check

        Returns
        -------
        bool
            returns True if an ARP REPLY was received for the given IP address
            returns False otherwise

        """

        tmp_ip = "0.0.0.0"
        print("Sending ARP request for IP: " + str(ip_addr))
        logging.info("Sending ARP request for IP: " + str(ip_addr))
        arp_request = self.make_arp_request(tmp_ip, ip_addr)
        arp_reply = srp1(arp_request, timeout=3, verbose=0)
        if arp_reply is not None:
            # print(arp_reply.display())
            print("Received ARP reply from IP: " + str(ip_addr))
            logging.info("Received ARP reply from IP: " + str(ip_addr))
        return arp_reply is not None

    def make_arp_request(self, ip_src, ip_dst):
        """
        Creates an ARP REQUEST packet

        Parameters
        ----------
        ip_src : str
            source IP address of the ARP REQUEST
        ip_dst : str
             destination IP address of the ARP REQUEST

        Returns
        -------
        Packet
            A scapy ARP REQUEST Packet

        """
        ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.mac_address)
        arp = ARP(op=1, hwsrc=self.mac_address, psrc=ip_src,
                  hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_dst)
        pkt = ether / arp
        return pkt

    @abstractmethod
    def connect(self):
        """
        Tries to discover connection settings analyzing network traffic and applying heuristics

        Returns
        -------
        bool
            return True if it is able to discover the network address, the subnet-mask, the default gateway and a free IP address
            return False otherwise

        """
        pass

    def configure_network(self):
        """
        Configures the interface with the connection settings: network, gateway, IP address

        Returns
        -------
        bool
            return True if all the settings are provided and the interface is up
            return False otherwise

        """
        if self.network is not None and self.gateway is not None and self.ip is not None:
            setup_interface(self.interface, str(self.ip), str(self.network.netmask))
            setup_default_gateway(str(self.gateway))
            setup_dns(str(self.gateway) + ",8.8.8.8")
            return True
        else:
            return False
