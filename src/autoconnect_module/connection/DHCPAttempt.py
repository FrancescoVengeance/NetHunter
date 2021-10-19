from connection.ConnectionAttempt import ConnectionAttempt
from util.Interface import *
from scapy.all import *
from scapy.layers.inet import IP, Ether, UDP
from scapy.layers.dhcp import BOOTP, DHCP


class DHCPAttempt(ConnectionAttempt):
    """
    A class used to represent a DHCP Connection Attempt

    Methods
    -------
    make_dhcp_discover()
        Creates a DHCPDISCOVER packet using scapy
    make_dhcp_request()
        Creates a DHCPREQUEST packet using scapy
    get_dhcp_option(dhcp_options, key)
        Extracts DHCP options by key
    connect()
        Tries to discover connection settings performing a DHCP handshake

    """

    def __init__(self, interface):
        ConnectionAttempt.__init__(self, interface)
        conf.checkIPaddr = False

    def make_dhcp_discover(self):
        """
        Creates a DHCPDISCOVER packet using scapy

        Returns
        -------
        Packet
            A scapy DHCPDISCOVER Packet

        """
        ethernet = Ether(src=self.mac_address, dst='ff:ff:ff:ff:ff:ff')
        ip = IP(src='0.0.0.0', dst='255.255.255.255')
        udp = UDP(dport=67, sport=68)
        bootp = BOOTP(chaddr=self.mac_address_raw, xid=RandInt())
        dhcp = DHCP(options=[('message-type', 'discover'), ("hostname", self.hostname), 'end'])
        dhcp_discover_pkt = ethernet / ip / udp / bootp / dhcp
        return dhcp_discover_pkt

    def make_dhcp_request(self, my_ip_address, server_id, xid):
        """
        Creates a DHCPREQUEST packet using scapy

        Parameters
        ---------
        my_ip_address : str
            the IP address assigned by the DHCP Server
        server_id : str
            the DHCP Server Identification
        xid : str
            the DHCP Transaction id

        Returns
        -------
        Packet
            A scapy DHCPREQUEST Packet

        """

        ethernet = Ether(src=self.mac_address, dst="ff:ff:ff:ff:ff:ff")
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(chaddr=self.mac_address_raw, xid=xid)
        dhcp = DHCP(options=[("message-type", "request"), ("server_id", server_id),
                             ("requested_addr", my_ip_address), ("hostname", self.hostname), "end"])

        dhcp_request = ethernet / ip / udp / bootp / dhcp
        return dhcp_request

    def get_dhcp_option(self, dhcp_options, key):
        """
        Extracts DHCP options by key

        Parameters
        ----------
        dhcp_options : vector of key-value pair
            DHCP options
        key : str
            The option key to extract

        Returns
        -------
        str
            The requested DHCP option

        """
        must_decode = ['hostname', 'domain', 'vendor_class_id']
        try:
            for i in dhcp_options:
                if i[0] == key:
                    # If DHCP Server returned multiple name servers
                    # return all as comma separated string.
                    if key == 'name_server' and len(i) > 2:
                        return ",".join(i[1:])
                    # domain and hostname are binary strings,
                    # decode to unicode string before returning
                    elif key in must_decode:
                        return i[1].decode()
                    else:
                        return i[1]
        except:
            pass

    def connect(self):
        """
        Tries to perform a DHCP handshake using scapy and setup the interface with the connection settings

        Returns
        -------
        bool
            returns True if there is a DHCP Server and the DHCP handshake is successful
            returns False otherwise

        """
        # DHCPDISCOVER -> DHCPOFFER -> DHCPREQUEST -> DHCPACK
        dhcp_discover_pkt = self.make_dhcp_discover()
        print("Sending DHCP Discover")
        logging.info("Sending DHCP Discover")
        dhcp_offer = srp1(dhcp_discover_pkt, iface=self.interface, verbose=0, timeout=5)
        if dhcp_offer is not None:
            my_ip_address = dhcp_offer[BOOTP].yiaddr
            server_id = self.get_dhcp_option(dhcp_offer[DHCP].options, 'server_id')
            xid = dhcp_offer[BOOTP].xid
            print("Received DHCP Offer: IP = %s" % my_ip_address)
            logging.info("Received DHCP Offer: IP = %s" % my_ip_address)
            dhcp_request = self.make_dhcp_request(my_ip_address, server_id, xid)
            print("Sending DHCP Request")
            logging.info("Sending DHCP Request")
            dhcp_ack = srp1(dhcp_request, iface=self.interface, verbose=0, timeout=5)
            if dhcp_ack is not None:
                print("Received DHCP ACK")
                logging.info("Received DHCP ACK")
                dhcp_options = dhcp_ack[DHCP].options
                subnet_mask = self.get_dhcp_option(dhcp_options, 'subnet_mask')
                broadcast_address = self.get_dhcp_option(dhcp_options, 'broadcast_address')
                router = self.get_dhcp_option(dhcp_options, 'router')
                dns_servers = self.get_dhcp_option(dhcp_options, 'name_server')
                print(subnet_mask, broadcast_address, router, dns_servers)
                logging.info("Subnetmask: " + str(subnet_mask))
                logging.info("Broadcast address: " + str(broadcast_address))
                logging.info("Default router: " + str(router))
                logging.info("DNS server addresses: " + str(router))
                setup_interface(self.interface, my_ip_address, subnet_mask)
                setup_default_gateway(router)
                setup_dns(dns_servers)
                return True
            else:
                return False
        else:
            print("No DHCP Server available!")
            logging.info("No DHCP Server available!")
            return False
        