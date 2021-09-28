from threading import Thread
from pyshark.packet.packet import Packet
from safe_print import SafePrint
from packets_buffer import PacketsBuffer
from time import sleep


# il monitor deve conoscere gli switch e le loro porte
# utilizzare naspy per generare un json con tutte le informazioni
class ARPMonitor(Thread):
    def __init__(self, packets_buffer: PacketsBuffer, safe_print: SafePrint):
        super().__init__()
        self.ip_arp_table: {str, list} = {}
        self.mac_arp_table: {str, list} = {}
        self.safe_print: SafePrint = safe_print
        self.packets_buffer: PacketsBuffer = packets_buffer

    def update_arp_table(self, packet: Packet, sender_port=None, target_port=None) -> None:
        sender_mac = packet.arp.src_hw_mac
        sender_ip = packet.arp.src_proto_ipv4
        target_mac = packet.arp.dst_hw_mac
        target_ip = packet.arp.dst_proto_ipv4

        # self.safe_print.print(f"sender {sender_mac} target {target_mac}")

        sender_vlan_id = 1
        target_vlan_id = 1

        if "type" in packet.eth.field_names and packet.eth.type == "0x00008100":
            sender_vlan_id = packet.vlan.id
            target_vlan_id = packet.vlan.id
        else:
            if sender_port is not None and not sender_port.trunk:
                sender_vlan_id = sender_port.pvlan_status[0]
            if target_port is not None and target_port.trunk:
                target_vlan_id = target_port.pvlan_status[0]

        if target_mac != "00:00:00:00:00:00" and target_mac != "ff:ff:ff:ff:ff:ff" and target_ip != "0.0.0.0":
            self.add_entry(target_ip, target_mac, target_vlan_id)
        if sender_mac != "00:00:00:00:00:00" and sender_mac != "ff:ff:ff:ff:ff:ff":
            self.add_entry(sender_ip, sender_mac, sender_vlan_id)

    def add_entry(self, ip: str, mac: str, vlan_id: str) -> None:
        if ip in self.ip_arp_table:
            if not ((mac, vlan_id) in self.ip_arp_table[ip]):
                self.ip_arp_table[ip].append((mac, vlan_id))
                if len(self.ip_arp_table[ip]) > 1:
                    self.check_ip_duplicate()
        else:
            self.ip_arp_table[ip] = []
            self.ip_arp_table[ip].append((mac, vlan_id))

        if mac in self.mac_arp_table:
            if not ((ip, vlan_id) in self.mac_arp_table[mac]):
                self.mac_arp_table[mac].append((ip, vlan_id))
                if len(self.mac_arp_table) > 1:
                    self.check_mac_duplicate()
        else:
            self.mac_arp_table[mac] = []
            self.mac_arp_table[mac].append((ip, vlan_id))

    def check_ip_duplicate(self) -> None:
        macs = {}
        for ip in self.ip_arp_table:
            for pair in self.ip_arp_table[ip]:
                for pair2 in self.ip_arp_table[ip]:
                    if pair[0] != pair2[0] and pair[1] == pair2[1]:
                        if ip in macs:
                            if pair not in macs[ip]:
                                macs[ip].append(pair)
                                macs[ip].append(pair2)
                            else:
                                macs[ip] = []
                                macs[ip].append(pair)
                                macs[ip].append(pair2)

        warning = False
        for ip in macs:
            if len(macs[ip]) > 1:
                warning = True
                break

        message = "f######## ARP STATUS ########\n"
        if warning:
            for ip in macs:
                if len(macs[ip]) > 1:
                    message += f"\t[WARNING] duplicate IP address [{ip}] with this MACs [{str(macs[ip])[1:-1]}]\n"
        else:
            message += "\tNothing to show\n"

        message += f"############################"
        self.safe_print.print(message)

    def check_mac_duplicate(self) -> None:
        ips = {}

        for mac in self.mac_arp_table:
            for pair in self.mac_arp_table[mac]:
                for pair2 in self.mac_arp_table[mac]:
                    if pair[0] != pair2[0] and pair[1] == pair2[1]:
                        if mac in ips:
                            if pair not in ips[mac]:
                                ips[mac].append(pair)
                            if pair2 not in ips[mac]:
                                ips[mac].append(pair2)
                        else:
                            ips[mac] = list()
                            ips[mac].append(pair)
                            ips[mac].append(pair2)

        warning = False
        for mac in ips:
            if len(ips[mac]) > 1:
                warning = True
                break

        message = "f######## ARP STATUS ########\n"
        if warning:
            for mac in ips:
                if len(ips[mac]) > 1:
                    message += f"\t[WARNING] duplicate MAC address [{mac}] with this IPs [{str(ips[mac])[1:-1]}]\n"
        else:
            message += "\tNothing to show\n"

        message += f"############################"
        self.safe_print.print(message)

    def run(self) -> None:
        while True:
            packet = self.packets_buffer.pop("ARP")
            if packet is not None:
                self.safe_print.print(f"ARP monitor")
                self.update_arp_table(packet)
            sleep(1)
