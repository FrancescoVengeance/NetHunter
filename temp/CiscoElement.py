from Element import *
import paramiko
import re
from utilities import EntryNotFoundException, ElementException
from paramiko import Channel


class CiscoElement(Element):
    def connectionSSH(self, database: dict) -> str:
        print(f"trying to connect to: {self.ip}", end="\n")
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

            self.getHostname(shell)
            self.showCDP(shell)
            self.showLLDP(shell)
            self.showArp(shell)
            self.showMacTable(shell)

            print(f"links found for {self.hostname}({self.ip}): {len(self.links)}")

        except EntryNotFoundException:
            print("unable to connect to SSH")
        finally:
            client.close()
            return self.hostname

    def showCDP(self, shell: Channel) -> None:
        print("loading CDP...")
        cdpBuffer = ""
        shell.send("show cdp neighbors detail\n")
        shell.send("\n")
        while not re.search('.*#\r\n.*#.*', cdpBuffer):
            if shell.recv_ready():
                response = shell.recv(9999).decode('ascii')
                cdpBuffer += response

        cdp = []
        if not re.search('.*CDP.*not.*', cdpBuffer):
            cdp = re.compile('--+').split(cdpBuffer)[1:]

        for text in cdp:
            self.parseCDP(text)

    def parseCDP(self, text: str) -> None:
        print("parsing CDP")
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

            print(f"found {element.hostname}")
            self.manager.addElement(hostname, element)

        link = Link(_from, to, element)
        if link not in self.links:
            self.addLink(link)

        if element not in self.manager.visited and element not in self.manager.toVisit:
            self.manager.addToVisit(element)

    def parseLLDP(self, shell: Channel) -> None:
        pass

    def parseMacTable(self, shell: Channel):
        pass

    def parseARP(self, shell: Channel):
        pass

    def getHostname(self, shell: Channel) -> None:
        #aggiustare anche inserendo il dominio
        print("getting hostname...")
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
