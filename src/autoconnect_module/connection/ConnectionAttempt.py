from abc import ABC, abstractmethod
from scapy.all import *


class ConnectionAttempt (ABC):

    """
    An abstract class used to represent a Connection Attempt

    Attributes
    ----------
    hostname : str
        the name of the host
    interface : str
        the name of the interface to connect
    mac_address : str
        the mac address of the interface to connect

    Methods
    -------
    connect()
        Tries to discover connection settings analyzing network traffic

    """
    def __init__(self, interface):
        self.hostname = 'raspberrypi'
        self.interface = interface
        self.mac_address = get_if_hwaddr(interface)
        self.fam, self.mac_address_raw = get_if_raw_hwaddr(interface)

    @abstractmethod
    def connect(self):
        """
        Tries to discover connection settings analyzing network traffic

        Returns
        -------
        bool
            returns True if it is able to discover the network address, the subnet-mask, the default gateway and a free IP address
            returns False otherwise

        """
        pass

