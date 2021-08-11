import json
import pyshark
from utilities import ElementsManager
from CiscoElement import CiscoElement
from Element import Element
import difflib


class Naspy:
    def __init__(self):
        self.manager = ElementsManager()
        self.database = self.decryptDB()

    @staticmethod
    def decryptDB() -> dict:
        print("Loading database...", end="\n")
        with open("../naspy_module/hosts.db", "rb") as file:
            data = file.read()

        database = json.loads(data.decode())
        return database

    def visit(self) -> None:
        found = False
        while self.manager.toVisit:
            element = self.manager.popToVisit()
            hostname = element.connectionSSH(self.database)
            if hostname != "":
                found = True
            self.manager.addToVisited(element)

        if found:
            print("\ndevice founded:")
            count = 1
            for hostname in self.manager.elementsByHostname:
                print(f"    [{count}]: {hostname}\n")
                count += 1
            self.buildJson()
            pass

    def sniff(self, interface: str):
        capture = pyshark.LiveCapture(interface=interface, display_filter="cdp or lldp")
        try:
            print("start sniffing", end="\n")
            captured = False
            elapsedTime = 0
            while not captured:
                capture.sniff(packet_count=1, timeout=2)
                elapsedTime += 2
                print(f"waiting for a packet... Elapsed time: {elapsedTime} seconds", end="\n")
                if capture:
                    print("GOT IT")
                    captured = True
                    capture.eventloop.close()

            packet = capture[0]

            if "cdp" in packet:
                hostname = packet.cdp.deviceid.strip()
                ip = packet.cdp.nrgyz_ip_address.strip()
                capabilities = packet.cdp.capabilities.strip()
                platform = packet.cdp.platform.strip()
            else:
                hostname = packet.lldp.tlv_system_name.strip()
                ip = packet.lldp.mgn_addr_ip4.strip()
                capabilities = packet.lldp.tlv_system_cap.strip()
                platform = packet.lldp.tlv_system_desc.strip()

            print(f"\n(root device) Device id: {hostname}, ip {ip}, capabilities {capabilities}, platform {platform}\n")

            rootElement = None
            if "Cisco" in platform:
                rootElement = CiscoElement(hostname, ip, capabilities, platform, self.manager)
            elif "EXOS" in platform:
                pass
                # rootElement = ExtremeElement(hostname, ip, capabilities, platform, self.manager)
            else:
                rootElement = Element(hostname, ip, capabilities, platform, self.manager)

            self.manager.addElement(hostname, rootElement)
            self.manager.addToVisit(rootElement)
            self.visit()

        finally:
            capture.eventloop.close()

    def buildJson(self) -> None:
        firstNode = True
        firstEdge = True
        nodes = '{"nodes":[\n\t'
        edges = '"edges":[\n\t'
        cont = 0
        computed = []

        for hostname in sorted(self.manager.elementsByHostname):
            if firstNode:
                nodes += '{"id":"' + self.manager.elementsByHostname[hostname].ip + '", "label":"' + hostname \
                         + '","x":0,"y":0,"size":1,"mac":"' \
                         + self.manager.getElementByHostname(hostname).macAddress + '"}'
                firstNode = False
            else:
                nodes += ',\n\t{"id":"' + self.manager.elementsByHostname[hostname].ip + '", "label":"' \
                         + hostname + '","x":0,"y":1,"size":1,"mac":"' \
                         + self.manager.getElementByHostname(hostname).macAddress + '"}'

            for link in self.manager.getElementByHostname(hostname).links:
                string = ""
                print(link.element.hostname.split("."))
                '''toAdd = link.element.hostname.split(".")
                string = "." + toAdd[1] + "." + toAdd[2]'''
                if (hostname + string, link.element.hostname) not in computed and (link.element.hostname, hostname + string) not in computed:
                    if firstEdge:
                        edges += '{"id":' + str(cont) + ', "source":"' + self.manager.elementsByHostname[hostname].ip \
                                 + '", "target": "' + link.element.ip \
                                 + '","from":"' + link.fr + '", "to":"' + link.to + '"}'
                        firstEdge = False
                    else:
                        edges += ',\n\t{"id":' + str(cont) + ', "source":"' + self.manager.elementsByHostname[hostname].ip \
                                 + '", "target": "' + link.element.ip \
                                 + '","from":"' + link.fr + '", "to":"' + link.to + '"}'
                    computed.append((hostname, link.element.hostname))
                    cont += 1

        nodes += '\n],'
        edges += '\n]}'
        s = nodes + edges
        nF = s.split('\n')

        with open('../naspy_module/Webpage/data.json') as f2:
            oldFile = f2.read()

        newElements = []
        for line in list(difflib.unified_diff(oldFile.split('\n'), nF, fromfile='oldFile', tofile='newFile', lineterm="\n"))[2:]:
            if line[len(line)-1] == ',':
                end = len(line)-2
            else:
                end = len(line)-1

            if '{' in line:
                if line[0] == '+':
                    newElements.append(line[1:end]+', "new":"true"}')
                if line[0] == '-':
                    newElements.append(line[1:end]+', "new":"false"}')

        toRemove = []
        for i in range(len(newElements)):
            je1 = json.loads(newElements[i])
            if 'source' in je1:
                toRemove.append(newElements[i])
            for j in range(i+1, len(newElements)):
                je2 = json.loads(newElements[j])
                if je1['id'] == je2['id'] and je1['new'] != je2['new']:
                    if newElements[i] not in toRemove:
                        toRemove.append(newElements[i])
                    if newElements[j] not in toRemove:
                        toRemove.append(newElements[j])

        for i in toRemove:
            if i in newElements:
                newElements.remove(i)

        diffFile = '{"items":['+",\n".join(newElements)+']}'

        with open('../naspy_module/Webpage/diff.json', 'w+') as d:
            d.write(diffFile)

        with open('../naspy_module/Webpage/data.json', 'w') as file:
            file.write("\n".join(nF))

    def manualConnection(self, ip: str):
        first = CiscoElement("", ip, "", "", self.manager)
        self.manager.addToVisit(first)
        self.visit()
