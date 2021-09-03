import json
import re
import paramiko
from paramiko.channel import Channel
from naspy.Link import Link
import subprocess


class Element:
    def __init__(self, hostname: str, ip: str, platform: str, capabilities: str, manager):
        self.hostname: str = hostname
        self.ip: str = ip
        self.platform: str = platform
        self.capabilities: str = capabilities
        self.manager = manager
        self.macAddress: str = ""
        self.links: list[Link] = []

    def __eq__(self, other) -> bool:
        return self.hostname == other.hostname

    def __hash__(self) -> int:
        return hash(self.hostname)

    def setMac(self, macAddress: str) -> None:
        self.macAddress = macAddress

    def addLink(self, link: Link) -> None:
        self.links.append(link)

    def toJson(self):
        return json.dumps(self, default=lambda o: o.__dict__)

    def connectionSSH(self, database: dict) -> str:
        print(f"trying to connect to {self.ip} \n unable to connect to SSH")
        self.getHostname(paramiko.SSHClient().invoke_shell())
        return ""

    def showCDP(self, shell: Channel) -> None:
        pass

    def parseCDP(self, text: str) -> None:
        pass

    def showLLDP(self, shell: Channel) -> None:
        pass

    def parseLLDP(self, text: str) -> None:
        pass

    def showArp(self, shell: Channel) -> None:
        pass

    def parseARP(self, text: str) -> None:
        pass

    def showMacTable(self, shell: Channel) -> None:
        pass

    def parseMacTable(self, text: list) -> None:
        pass

    def getHostname(self, shell: Channel) -> None:
        print(f"no information found for {self.ip}, trying port-scanning")
        output = subprocess.run(["nmap", "-O", self.ip], stdout=subprocess.PIPE, text=True)
        out = output.stdout.split("\n")
        for line in out:
            if re.search('OS details:(.*)', line):
                self.hostname = re.search('OS details:(.*)', line).group(1).strip()
