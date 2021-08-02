import json
import re
from Link import Link
import subprocess


class Element:
    """
    An abstract class modeling an element in the topology
    ----------
    type : str
        the typology of element
    name : str
        the name of the element
    platform : str
        the platform of the element
    ip : str
        the IP address of the element
    mac : str
        the MAC address of the element
    links : list(Link)
        the list of links of the element
    Methods
    -------
    connectionSSH()
        Perform the connection to SSH to the element
    addLink()
        Adds a link to the list of links
    addMac()
        Adds the MAC address to the element
    """

    def __init__(self, type, name, platform, ip, inspector):
        self.type = type
        self.name = name
        self.inspector = inspector
        self.platform = platform
        self.ip = ip
        self.mac = ''
        self.links = []
        #self.connectedDevices = 0

    def __eq__(self, other):
        return self.ip == other.ip

    def __hash__(self):
        return hash(self.ip)

    def addMac(self, mac: str):
        """
        Adds the MAC address to the element

        Parameters
        ----------
        mac:str
            the MAC address to add

        """
        self.mac = mac

    def addLink(self, link: Link):
        """
        Adds a link to the list of links

        Parameters
        ----------
        link:Link
            the link to add

        """
        self.links.append(link)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__)

    def connectionSSH(self, db: dict) -> int:
        """
        Perform the connection to SSH to the element

        Parameters
        ----------
        db:dict
            the dictionary of credentials

        Returns
        -------
        int
            returns the count of elements found

        """
        print("\ntrying to connect to: " + self.ip + "\n\nunable to connect to SSH")
        self.deviceScan()
        return 0

    def parseCDP(self, text: str):
        """
        Parses an entry for CDP table

        Parameters
        ----------
        text:str
            the text to parse
        """
        pass

    def parseLLDP(self, text: str):
        """
        Parses an entry of the LLDP table

        Parameters
        ----------
        text:str
            the text to parse
        """
        pass

    def parseArp(self, text: str):
        """
        Parses an ARP Table

        Parameters
        ----------
        text:str
            the text to parse
        """
        pass

    def parseMacTable(self, text: str):
        """
        Parses a mac Table

        Parameters
        ----------
        text:str
            the text to parse
        """
        pass

    def deviceScan(self):
        print(f"no information found for {self.ip}, trying port-scanning")
        output = subprocess.run(["nmap", "-O", self.ip], stdout=subprocess.PIPE, text=True)
        out = output.stdout.split("\n")
        for line in out:
            if re.search('OS details:(.*)', line):
                self.name = re.search('OS details:(.*)', line).group(1).strip()


class EntryNotFoundException(Exception):
    """
    An exception raised if the entry is not present in the
    database of credentials
    """
    pass


class ElementException(Exception):
    """
    An exception raised if the element was instantiated with the wrong class
    """
    pass