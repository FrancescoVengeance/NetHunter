from Element import *
from ExtremeElement import ExtremeElement
import paramiko
import re


class CiscoElement(Element):
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
        # list = []
        #ip = self.ip
        count = 0
        print("\ntrying to connect to: " + self.ip + "\n")
        client = paramiko.SSHClient()
        try:
            if self.ip not in db:
                raise EntryNotFoundException
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=self.ip, username=db[self.ip]['user'], password=db[self.ip]['pass'])

            sh = client.invoke_shell()
            sh.send("en\n")
            resp = ''
            while not re.search('.*Password.*', resp):
                if sh.recv_ready():
                    resp = sh.recv(9999).decode('ascii')
                    if 'Incomplete' in resp:
                        raise ElementException

            sh.send(db[self.ip]['en'] + "\n")
            sh.send("terminal length 0\n")
            sh.send("show lldp neighbors detail\n")
            sh.send("\n")
            lldpbuff = ''

            while not re.search('.*#\r\n.*#.*', lldpbuff):
                if sh.recv_ready():
                    resp = sh.recv(9999).decode('ascii')
                    lldpbuff += resp

            lldp = []
            if not re.search('.*LLDP.*not.*', lldpbuff):
                lldp = re.compile('--+').split(lldpbuff)[1:]

            for text in lldp:
                if self.parseLLDP(text):
                    count += 1

            cdpbuff = ''
            sh.send("show cdp neighbors detail\n")
            sh.send("\n")
            while not re.search('.*#\r\n.*#.*', cdpbuff):
                if sh.recv_ready():
                    resp = sh.recv(9999).decode('ascii')
                    cdpbuff += resp
            cdp = []
            if not re.search('.*CDP.*not.*', cdpbuff):
                cdp = re.compile('--+').split(cdpbuff)[1:]

            for text in cdp:
                if self.parseCDP(text):
                    count += 1

            buff = ''
            sh.send("show ip arp\n")
            sh.send("\n")

            while not re.search('.*#\r\n.*#.*', buff):
                if sh.recv_ready():
                    resp = sh.recv(9999).decode('ascii')
                    buff += resp

            arp = buff.split("\n")
            arp = arp[2:(len(arp) - 2)]

            for text in arp:
                if self.parseArp(text):
                    count += 1

            buff = ''
            sh.send("show mac address-table\n")
            sh.send("\n")

            while not re.search('.*#\r\n.*#.*', buff):
                if sh.recv_ready():
                    resp = sh.recv(9999).decode('ascii')
                    buff += resp

            sh.send("exit\r\n")

            mac_table = buff.split("\n")
            mac_table = mac_table[6:(len(mac_table) - 3)]

            count += self.parseMacTable(mac_table)

            print('links found for ' + self.ip + ': ' + str(count))

        except EntryNotFoundException:
            print('unable to connect to SSH')
            self.deviceScan()
        finally:
            client.close()
            return count

    def parseCDP(self, text: str) -> bool:
        """
        Parses an entry for CDP table

        Parameters
        ----------
        text:str
            the text to parse

        Returns
        -------
        bool
            returns true if the element is added, false otherwise

        """
        added = False
        try:
            s = text.split("\n")
            name = ip = fr = to = plat = capa = 'Unknown'

            for t in s:
                if re.search('Device ID: (.*)', t):
                    name = re.search('Device ID: (.*)', t).group(1).strip()
                elif re.search('.*IP address: (.*)', t):
                    ip = re.search('.*IP address: (.*)', t).group(1).strip()
                elif re.search('.*Interface:.*', t):
                    ports = t.split(',')
                    fr = re.search('.*: (.*)', ports[0]).group(1).strip()
                    to = re.search('.*: (.*)', ports[1]).group(1).strip()
                elif re.search('.*Platform:.*', t):
                    info = t.split(',')
                    plat = re.search('.*Platform: (.*)', info[0]).group(1).strip()
                    capa = re.search('.*Capabilities: (.*)', info[1]).group(1).strip()

            if 'EXOS' in plat or 'Extreme' in plat:
                to = 'Port ' + to

            if ip in self.inspector.elements and isinstance(self.inspector.elements[ip], (ExtremeElement, CiscoElement)):
                element = self.inspector.elements[ip]
                if element.type == 'Unknown':
                    element.type = capa
                if element.platform == 'Unknown':
                    element.platform = plat
                if element.name == 'Unknown':
                    element.name = name

            else:
                if 'Cisco' in plat:
                    element = CiscoElement(capa, name, plat, ip, self.inspector)
                elif 'EXOS' in plat or 'Extreme' in plat:
                    element = ExtremeElement(capa, name, plat, ip, self.inspector)
                else:
                    element = Element(capa, name, plat, ip, self.inspector)
                self.inspector.elements[ip] = element

            link = Link(fr, to, element)

            if link not in self.links:
                added = True
                self.addLink(link)

            if ip not in self.inspector.visited and ip not in self.inspector.toVisit:
                self.inspector.toVisit.append(ip)
        except:
            print('found new element but not enough information to be added\n')
        finally:
            return added

    def parseLLDP(self, text: str) ->bool:
        """
        Parses an entry of the LLDP table

        Parameters
        ----------
        text:str
            the text to parse

        Returns
        -------
        bool
            returns true if the element is added, false otherwise

        """

        added = False
        try:
            s = text.split("\n")

            name = ip = fr = to = capa = plat = 'Unknown'

            for t in s:
                if re.search('System Name: (.*)', t):
                    name = re.search('System Name: (.*)', t).group(1).strip()
                elif re.search('.*IP: (.*)', t):
                    ip = re.search('.*IP: (.*)', t).group(1).strip()
                elif re.search('Local Intf: (.*)', t):
                    fr = re.search('Local Intf: (.*)', t).group(1).strip()
                elif re.search('Port id: (.*)', t):
                    to = re.search('.*: (.*)', t).group(1).strip()
                elif re.search('.*System Capabilities: (.*)', t):
                    capa = re.search('.*System Capabilities: (.*)', t).group(1).strip()
                elif re.search('.*System Description: (.*)', t):
                    plat = s[s.index(t) + 1].strip()

            if ip in self.inspector.elements and isinstance(self.inspector.elements[ip], (ExtremeElement, CiscoElement)):
                element = self.inspector.elements[ip]
                if element.type == 'Unknown':
                    element.type = capa
                if element.platform == 'Unknown':
                    element.platform = plat
                if element.name == 'Unknown':
                    element.name = name
            else:
                if 'Cisco' in plat:
                    element = CiscoElement(capa, name, plat, ip, self.inspector)
                elif 'Extreme' in plat or 'EXOS' in plat:
                    element = ExtremeElement(capa, name, plat, ip, self.inspector)
                else:
                    element = Element(capa, name, plat, ip, self.inspector)
                self.inspector.elements[ip] = element

            link = Link(fr, to, element)

            if link not in self.links:
                added = True
                self.addLink(link)

            if ip not in self.inspector.visited and ip not in self.inspector.toVisit:
                self.inspector.toVisit.append(ip)
        except:
            print('found new element but not enough information to be added\n')
        finally:
            return added

    def parseArp(self, text: str):
        """
        Parses an ARP Table

        Parameters
        ----------
        text:str
            the text to parse
        """

        text = re.compile('\s\s+').split(text)
        ip = text[1]
        mac = text[3]

        element = None

        if ip in self.inspector.elements:
            element = self.inspector.elements[ip]
        else:
            element = Element("Unknown", "Unknown", "Unknown", ip, self.inspector)
            self.inspector.elements[ip] = element

        element.addMac(mac)

        self.inspector.elementsByMac[mac] = element

    def parseMacTable(self, text: str):
        """
        Parses a mac Table

        Parameters
        ----------
        text:str
            the text to parse

        Returns
        -------
        int
            returns the count of elements found

        """

        added = 0
        single_occurrences = []

        for i in range(len(text)):
            r1 = re.compile('\s\s+').split(text[i])
            found = False
            for j in range(len(text)):
                r2 = re.compile('\s\s+').split(text[j])
                if r1[4] == r2[4] and r1[2] != r2[2]:
                    found = True
            if not found:
                single_occurrences.append(r1)

        for entry in single_occurrences:
            if entry[2] in self.inspector.elementsByMac:
                element = self.inspector.elementsByMac[entry[2]]

                link = Link(entry[4].strip(), 'Unknown', element)

                if link not in self.links:
                    added += 1
                    self.addLink(link)

                if element.ip not in self.inspector.visited and element.ip not in self.inspector.toVisit:
                    self.inspector.toVisit.append(element.ip)
        return added
