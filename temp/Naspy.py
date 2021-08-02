import difflib
import json
import pyshark
from utilities import ElementsManager


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
            ip = self.manager.popToVisit()
            element = self.manager.getElementByIp(ip)
            hostname = element.connectionSSH(self.database)
            if hostname:
                found = True
            self.manager.addElement(element.name, element)

        if found:
            # self.buildJSON()
            pass

    def sniff(self, interface: str):
        capture = pyshark.LiveCapture(interface=interface, display_filter="cdp or lldp")
        try:
            print("start sniffing", end="\n")
            captured = False
            elapsedTime = 0
            while not captured:
                capture.sniff(packet_count=1, timeout=1)
                elapsedTime += 1
                print(f"waiting for a packet... Elapsed time: {elapsedTime} seconds", end="\n")
                if capture:
                    print("GOT IT")
                    captured = True

            packet = capture[0]
            rootElement = None

            if "cdp" in packet:
                name = packet.cdp.deviceid.strip()
                ip = packet.cdp.nrgyz_ip_address.strip()
                capabilities = packet.cdp.capabilities.strip()
                platform = packet.cdp.platform.strip()
            else:
                name = packet.lldp.tlv_system_name.strip()
                ip = packet.lldp.mgn_addr_ip4.strip()
                capabilities = packet.lldp.tlv_system_cap.strip()
                platform = packet.lldp.tlv_system_desc.strip()

            print(f"Device id: {name}, ip {ip}, capabilities {capabilities}, platform {platform}")

        finally:
            capture.eventloop.close()
            capture.close()
