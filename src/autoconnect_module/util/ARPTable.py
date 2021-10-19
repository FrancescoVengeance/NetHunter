import logging


class ARPTableEntry:
    """
    A class used to represent an ARP Table Entry.

    Attributes
    ----------
    ip_address : str
        IP address
    mac_address : str
        MAC address
    count : int
        number of occurrences of the IP address in ARP packets

    """

    def __init__(self, ip_address, mac_address):
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.count = 1


class ARPTable:
    """
    A class used to represent an ARP Table

    Attributes
    ----------
    table : dict[str, ARPTableEntry]
        a dictionary of ARPTableEntry indexed by IP address

    """
    def __init__(self):
        self.table = {}

    def add_or_update_entry(self, ip_address, mac_address):
        """
        Adds the IP address in the ARP Table or updates the existing table entry incrementing the number of occurrences

        Parameters
        ---------
        ip_address : str
            IP address
        mac_address : str
            MAC address

        """

        entry = self.table.get(ip_address)
        if entry is None:
            self.table[ip_address] = ARPTableEntry(ip_address, mac_address)
        else:
            if mac_address != 'ff:ff:ff:ff:ff:ff' and entry.mac_address == 'ff:ff:ff:ff:ff:ff':
                entry.mac_address = mac_address
            entry.count += 1

    def print(self):
        """
        Prints the ARP Table
        """
        print("\n")
        logging.info("\n")
        for entry in self.table:
            print(self.table[entry].ip_address + "\t" + self.table[entry].mac_address + "\t" +
                  str(self.table[entry].count))
            logging.info(self.table[entry].ip_address + "\t" + self.table[entry].mac_address + "\t" + str(self.table[entry].count))

    def contains(self, ip_address):
        """
        Checks if the IP address is present in the ARP Table

        Parameters
        ---------
        ip_address : str
            IP address to checks

        Returns
        -------
        bool
            returns True if the ARP Table contains the IP address
            returns False otherwise

        """
        return ip_address in self.table
