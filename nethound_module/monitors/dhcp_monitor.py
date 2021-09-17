from threading import Thread
from time import sleep
from packets_queue import PacketsQueue
from network_elements.dhcp_server import DHCPServer
from safe_print import SafePrint
from scapy.arch import get_if_hwaddr, get_if_raw_hwaddr
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp
from pyshark.packet.packet import Packet


class DHCPMonitor(Thread):
    def __init__(self, interface: str, packets: PacketsQueue, safe_print: SafePrint):
        super().__init__()
        self.interface: str = interface
        self.dhcp_servers: list[DHCPServer] = []
        self.packets: PacketsQueue = packets
        self.safe_print: SafePrint = safe_print

    def update_dhcp_servers(self, packet: Packet):
        # if packet.bootp.option_dhcp == "2":
        #     ip = packet.bootp.option_dhcp_server_id
        #     mac = packet.eth.src
        if True:
            ip = packet.layers
            self.safe_print.print(f"DHCP {packet.dhcp.src}")
            mac = packet.ip.src
            subnet = "0.0.0.0"
            # if "option_subnet_mask" in packet.bootp.field_names:
            #     subnet = packet.bootp.option_subnet_mask

            if len(self.dhcp_servers) > 0:
                found = False
                for server in self.dhcp_servers:
                    if server.mac == mac:
                        server.restore_no_response_count()
                        found = True
                if not found:
                    self.add_new_dhcp_server(ip, mac, subnet)
            else:
                self.add_new_dhcp_server(ip, mac, subnet)

    def add_new_dhcp_server(self, ip: str, mac: str, subnet: str) -> None:
        new_dhcp_server = DHCPServer(ip, mac, subnet)
        self.dhcp_servers.append(new_dhcp_server)
        message = f"New DHCP Server discovered!\n\t\t IP: {ip} | MAC: {mac} | Subnet: {subnet}"
        self.safe_print.print(message)

    def increase_counter(self) -> None:
        for server in self.dhcp_servers:
            if server.no_response_count > 2:
                self.safe_print.print(f"DHCP server [{server.ip}] is no longer available")
                self.dhcp_servers.remove(server)
            server.increase_no_response_count()

    def print_status(self) -> None:
        message = "######## DHCP STATUS ########"
        if len(self.dhcp_servers) == 0:
            message += "\n\t No DHCP Servers found! \t\t\n"
        else:
            message += "\n"
            for server in self.dhcp_servers:
                message += f"\t\t{server.get_info()}\n"

        message += "#############################"
        self.safe_print.print(message)

    def send_dhcp_discover(self) -> None:
        self.safe_print.print("sending DHCP discover...")
        local_mac = get_if_hwaddr(self.interface)
        fam, local_raw_mac = get_if_raw_hwaddr(self.interface)
        broadcast_mac = "ff:ff:ff:ff:ff:ff"
        source_ip = "0.0.0.0"
        dest_ip = "255.255.255.255"

        dhcp_discover = Ether(src=local_mac, dst=broadcast_mac) / IP(src=source_ip, dst=dest_ip) / UDP(
            dport=67, sport=68) / BOOTP(chaddr=local_raw_mac) / DHCP(options=[("message-type", "discover"), "end"])
        sendp(dhcp_discover, iface=self.interface, count=15, inter=0.5, verbose=False)

    def run(self) -> None:
        stop = False
        while not stop:
            try:
                self.send_dhcp_discover()
                packet = self.packets.pop("DHCP")
                if packet is not None:
                    self.update_dhcp_servers(packet)
                self.print_status()
                sleep(3)
            except KeyboardInterrupt:
                stop = True
