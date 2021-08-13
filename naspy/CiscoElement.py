from Element import *
import paramiko
import re
from utilities import EntryNotFoundException, ElementException
from paramiko import Channel
import traceback

class CiscoElement(Element):
    def connectionSSH(self, database: dict) -> str:
        print(f"\ntrying to connect to: {self.ip}", end="\n")
        client = paramiko.SSHClient()

        try:
            if self.ip not in database:
                raise EntryNotFoundException

            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=self.ip, username=database[self.ip]['username'],
                           password=database[self.ip]["password"])
            shell: Channel = client.invoke_shell()
            shell.send("en\n")
            response = ""

            while not re.search(".*Password.*", response):
                if shell.recv_ready():
                    response = shell.recv(9999).decode("ascii")
                    if "Incomplete" in response:
                        raise ElementException

            shell.send(database[self.ip]['enable'] + "\n")
            shell.send("terminal length 0\n")

            print("getting hostname...")
            self.getHostname(shell)

            print("parsing CDP...")
            self.showCDP(shell)

            print("parsing LLDP...")
            self.showLLDP(shell)

            print("parsing ARP table...")
            self.showArp(shell)

            print("parsing mac table...")
            self.showMacTable(shell)

            shell.send("exit\r\n")
            print(f"links found for {self.hostname}({self.ip}): {len(self.links)}")

        except EntryNotFoundException:
            print("unable to connect to SSH")
        finally:
            client.close()
            return self.hostname

    def showCDP(self, shell: Channel) -> None:
        cdpBuffer = ""
        shell.send("show cdp neighbors detail\n")
        shell.send("\n")
        while not re.search('.*#\r\n.*#.*', cdpBuffer):
            if shell.recv_ready():
                cdpBuffer += shell.recv(9999).decode('ascii')

        cdp = []
        if not re.search('.*CDP.*not.*', cdpBuffer):
            cdp = re.compile('--+').split(cdpBuffer)[1:]

        for text in cdp:
            self.parseCDP(text)

    def parseCDP(self, text: str) -> None:
        strings = text.split("\n")
        hostname = ip = _from = to = platform = capabilities = ""

        for line in strings:
            if re.search('Device ID: (.*)', line):
                hostname = re.search('Device ID: (.*)', line).group(1).strip()
            elif re.search('.*IP address: (.*)', line):
                ip = re.search('.*IP address: (.*)', line).group(1).strip()
            elif re.search('.*Interface:.*', line):
                ports = line.split(',')
                _from = re.search('.*: (.*)', ports[0]).group(1).strip()
                to = re.search('.*: (.*)', ports[1]).group(1).strip()
            elif re.search('.*Platform:.*', line):
                info = line.split(',')
                platform = re.search('.*Platform: (.*)', info[0]).group(1).strip()
                capabilities = re.search('.*Capabilities: (.*)', info[1]).group(1).strip()

        if "EXOS" in platform or "Extreme" in platform:
            to = "Port " + to

        element = None
        if hostname in self.manager.elementsByHostname and isinstance(self.manager.getElementByHostname(hostname), CiscoElement):
            element = self.manager.getElementByHostname(hostname)
            if element.capabilities == "":
                element.capabilities = capabilities
            if element.platform == "":
                element.platform = platform
            if element.hostname == "":
                element.hostname = hostname
        else:
            if "Cisco" in platform:
                element = CiscoElement(hostname, ip, platform, capabilities, self.manager)
            elif "EXOS" in platform or "Extreme" in platform:
                pass
            else:
                element = Element(hostname, ip, platform, capabilities, self.manager)

            print(f"    found {element.hostname}")
            self.manager.addElement(hostname, element)

        link = Link(_from, to, element)
        if link not in self.links:
            self.addLink(link)

        if element not in self.manager.visited and element not in self.manager.toVisit:
            self.manager.addToVisit(element)

    def parseLLDP(self, shell: Channel) -> None:
        pass

    def showMacTable(self, shell: Channel) -> None:
        buffer = ""
        shell.send("show mac address-table\n")
        shell.send("\n")

        while not re.search('.*#\r\n.*#.*', buffer):
            if shell.recv_ready():
                buffer += shell.recv(9999).decode("ascii")

        macTable = buffer.split("\n")
        macTable = macTable[6:(len(macTable) - 3)]
        self.parseMacTable(macTable)

    def parseMacTable(self, text: list):
        singleOccurrences = []

        for i in range(len(text)):
            r1 = re.compile("\s\s+").split(text[i])
            found = False
            for j in range(len(text)):
                r2 = re.compile("\s\s+").split(text[j])
                if r1[4] == r2[4] and r1[2] != r2[2]:
                    found = True
            if not found:
                singleOccurrences.append(r1)

        element = None
        link = None
        for entry in singleOccurrences:
            if self.manager.getElementByMac(entry[2]) is not None:
                element = self.manager.getElementByMac(entry[2])
                link = Link(entry[4].strip(), "Unknown", element)

            if link not in self.links:
                self.addLink(link)

            if element not in self.manager.visited and element not in self.manager.toVisit:
                self.manager.addToVisit(element)

    def showArp(self, shell: Channel) -> None:
        buffer = ""
        shell.send("show ip arp\n")
        shell.send("\n")

        while not re.search(".*#\r\n.*#.*", buffer):
            if shell.recv_ready():
                buffer += shell.recv(9999).decode("ascii")

        arpTable = buffer.split("\n")
        arpTable = arpTable[2:(len(arpTable) - 2)]

        for line in arpTable:
            self.parseARP(line)

    def parseARP(self, text: str) -> None:
        print("parsing arp")
        text = re.compile("\s\s+").split(text)
        ip = text[0]
        mac = text[3]

        try:
            element = self.manager.getElementByIp(ip)
            if element is None:
                element = Element("", ip, "", "", self.manager)
            element.setMac(mac)
        except Exception:
            traceback.print_exc()


    def getHostname(self, shell: Channel) -> None:
        # aggiustare anche inserendo il dominio
        shell.send("show running-config\n")
        shell.send("\n")

        out = ""
        while not re.search('hostname (.*)', out):
            if shell.recv_ready():
                out += shell.recv(9999).decode("ascii")

        for line in out.split("\n"):
            if re.search('hostname (.*)', line):
                self.hostname = re.search('hostname (.*)', line).group(1).strip()
                break
