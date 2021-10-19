class RARPTableEntry:
    """
    A class used to represent a RARP Table Entry.

    Attributes
    ----------
    ip_address : str
        IP address
    in_arp : bool
        flag to mark IP addresses that comes from ARP packets.
    """
    def __init__(self, ip_address, in_arp):
        self.ip_address = ip_address
        self.in_arp = in_arp

    def __eq__(self, other):
        return self.ip_address == other.ip_address and self.in_arp == other.in_arp

    def __hash__(self):
        return hash(self.ip_address + str(self.in_arp))


class RARPTable:
    """
    A class used to represent a RARP Table

    Attributes
    ----------
    table : dict[str, set[RARPTableEntry]]
    """
    def __init__(self):
        self.table = {}

    def add_or_update_entry(self, mac_address, ip_address, in_arp):
        """
        Adds the IP address in the set of IP address associated with the MAC address.

        Parameters
        ---------
        mac_address : str
            MAC address
        ip_address : str
            IP address
        in_arp : bool
            flag to mark IP addresses that comes from ARP packets
        """
        entry = self.table.get(mac_address)
        if entry is None:
            s = set()
            s.add(RARPTableEntry(ip_address, in_arp))
            self.table[mac_address] = s
        else:
            s = self.table[mac_address]
            s.add(RARPTableEntry(ip_address, in_arp))

    def print(self):
        """
        Prints the RARP Table
        """
        for mac in self.table:
            print(mac + "    ->      ", end='')
            for entry in self.table[mac]:
                print(entry.ip_address, entry.in_arp, end=' ')
            print()

