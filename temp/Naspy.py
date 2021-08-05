import difflib
import json
import pyshark
from utilities import ElementsManager
from CiscoElement import CiscoElement
from Element import Element


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
        found = True
        while self.manager.toVisit:
            element = self.manager.popToVisit()
            # element = self.manager.getElementByIp(ip)
            hostname = element.connectionSSH(self.database)
            if hostname != "":
                found = True
            self.manager.addToVisited(element)

        if found:
            # self.buildJSON()
            pass

    async def sniff(self, interface: str):
        capture = pyshark.LiveCapture(interface=interface, display_filter="cdp or lldp")
        try:
            print("start sniffing", end="\n")
            captured = False
            elapsedTime = 0
            while not captured:
                await capture.sniff(packet_count=1, timeout=2)
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
                #rootElement = ExtremeElement(hostname, ip, capabilities, platform, self.manager)
            else:
                rootElement = Element(hostname, ip, capabilities, platform, self.manager)

            self.manager.addElement(hostname, rootElement)
            self.manager.addToVisit(rootElement)
            self.visit()

        finally:
            capture.eventloop.close()
            capture.close()
