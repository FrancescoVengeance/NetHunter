from Element import Element
from CiscoElement import CiscoElement
import json
import difflib
import pyshark


class Inspector:
    def __init__(self):
        self.toVisit = []
        self.visited = []
        self.elements = {}
        self.elementsByMac = {}
        self.database = self.decryptDB()

    def decryptDB(self) -> dict:
        print("Loading database...", end="\n")
        with open("../naspy_module/hosts.db" , "rb") as file:
            data = file.read()

        database = json.loads(data.decode())
        return database

    def visit(self) -> None:
        found = False
        while self.toVisit:
            ip = self.toVisit.pop(0)
            element = self.elements[ip]
            if element.connectionSSH(self.database) > 0:
                found = True
            self.visited.append(ip)

        if found:
            #usa nmap per quelli unknown
            self.buildJSON()

    def removeDuplicate(self):
        keysToRemove = []
        for key in self.elements.keys():
            for key2 in self.elements.keys():
                if self.elements[key] == self.elements[key2]:
                    pass
                elif self.elements[key].name == self.elements[key2].name:
                    if len(self.elements[key].links) > len(self.elements[key2].links):
                        keysToRemove.append(key2)
                    else:
                        keysToRemove.append(key)

        for key in keysToRemove:
            if key in self.elements.keys():
                self.elements.pop(key)

    def buildJSON(self):
        first = True
        firstE = True
        nodes = '{"nodes":[\n\t'
        edges = '"edges":[\n\t'
        cont = 0
        computed = []
        # self.removeDuplicate()

        for ip in sorted(self.elements.keys()):
            if first:
                nodes += '{"id":"' + ip + '", "label":"' + self.elements[ip].name + '","x":0,"y":0,"size":1,"mac":"' + self.elements[ip].mac + '"}'
                first = False
            else:
                nodes += ',\n\t{"id":"' + ip + '", "label":"' + self.elements[ip].name + '","x":0,"y":1,"size":1,"mac":"' + self.elements[ip].mac + '"}'
            for edge in self.elements[ip].links:
                if (ip, edge.element.ip) not in computed and (edge.element.ip, ip) not in computed:
                    if firstE:
                        edges += '{"id":' + str(
                            cont) + ', "source":"' + ip + '", "target": "' + edge.element.ip + '","from":"' + edge.port1 + '", "to":"' + edge.port2 + '"}'
                        firstE = False
                    else:
                        edges += ',\n\t{"id":' + str(
                            cont) + ', "source":"' + ip + '", "target": "' + edge.element.ip + '","from":"' + edge.port1 + '", "to":"' + edge.port2 + '"}'
                    computed.append((ip, edge.element.ip))
                    cont += 1

        nodes += '\n],'
        edges += '\n]}'

        s = nodes + edges

        nF = s.split('\n')
        with open('../naspy_module/Webpage/data.json') as f2:
            oldFile = f2.read()

        newElements = []
        for line in list(
                difflib.unified_diff(oldFile.split('\n'), nF, fromfile='oldFile', tofile='newFile', lineterm="\n"))[2:]:
            end = 0
            if line[len(line) - 1] == ',':
                end = len(line) - 2
            else:
                end = len(line) - 1

            if '{' in line:
                if line[0] == '+':
                    newElements.append(line[1:end] + ', "new":"true"}')
                if line[0] == '-':
                    newElements.append(line[1:end] + ', "new":"false"}')

        toRemove = []
        for i in range(len(newElements)):
            je1 = json.loads(newElements[i])
            if 'source' in je1:
                toRemove.append(newElements[i])
            for j in range(i + 1, len(newElements)):
                je2 = json.loads(newElements[j])
                if (je1['id'] == je2['id'] and je1['new'] != je2['new']):
                    if newElements[i] not in toRemove:
                        toRemove.append(newElements[i])
                    if newElements[j] not in toRemove:
                        toRemove.append(newElements[j])

        for i in toRemove:
            if i in newElements:
                newElements.remove(i)

        diffFile = '{"items":[' + ",\n".join(newElements) + ']}'

        with open('../naspy_module/Webpage/diff.json', 'w') as d:
            d.write(diffFile)

        with open('../naspy_module/Webpage/data.json', 'w') as file:
            file.write("\n".join(nF))

        '''newFile = self.generateNodesAndEdges().split("\n")
        with open("../naspy_module/Webpage/data.json") as file:
            oldFile = file.read()
        newElements = self.fetchNewElements(oldFile, newFile)
        newElements = self.removeOldElements(newElements)

        diffFile = '{"items":[' + ",\n".join(newElements) + ']}'
        with open("../naspy_module/Webpage/diff.json", "w") as file:
            file.write(diffFile)
        with open("../naspy_module/Webpage/data.json", "w") as file:
            file.write("\n".join(newFile))'''

    def sniff(self, interface: str):
        capture = pyshark.LiveCapture(interface=interface, display_filter="cdp or lldp")
        try:
            print("start sniffing", end="\n")
            captured = False
            while not captured:
                print("waiting to receive a packet...", end="\n")
                capture.sniff(packet_count=1, timeout=2)
                if capture:
                    print("GOT IT!")
                    captured = True
                    capture.eventloop.close()

            if capture:
                packet = capture[0]
                root = None
                if "cdp" in packet:
                    id = packet.cdp.deviceid.strip()
                    ip = packet.cdp.nrgyz_ip_address.strip()
                    capabilities = packet.cdp.capabilities.strip()
                    platform = packet.cdp.platform.strip()
                else:
                    id = packet.lldp.tlv_system_name.strip()
                    ip = packet.lldp.mgn_addr_ip4.strip()
                    capabilities = packet.lldp.tlv_system_cap.strip()
                    platform = packet.lldp.tlv_system_desc.strip()

                if "Cisco" in platform:
                    root = CiscoElement(capabilities, id, platform, ip, self)
                elif "EXOS" in platform:
                    root = None  # ExtremeElement(capabilities, id, platform, ip)
                else:
                    root = Element(capabilities, id, platform, ip, self)

                self.elements[ip] = root
                self.toVisit.append(ip)
                self.visit()
        finally:
            capture.eventloop.close()

    def manualConnection(self, ip):
        first = CiscoElement("Unknown", "Unknown", "Unknown", ip, self)
        self.elements[ip] = first
        self.toVisit.append(ip)
        self.visit()
        #se non riesco a connettermi provare con un Extreme
