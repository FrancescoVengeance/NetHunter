import time
from threading import Thread

import colorama
import pyshark
from dhcp_server import DHCPServer
from safe_print import SafePrint
from scapy.arch import get_if_hwaddr, get_if_raw_hwaddr
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp
from pyshark.packet.packet import Packet
from colorama import Fore as color


class DHCPMonitor(Thread):
    def __init__(self, interface: str, safe_print: SafePrint, timeout: int = 10):
        super().__init__()
        colorama.init(autoreset=True)
        self.interface: str = interface
        self.timeout = timeout
        self.dhcp_servers: list[DHCPServer] = []
        self.safe_print: SafePrint = safe_print
        self.display_filter = "dhcp"  # for dhcp offer
        self.capture = pyshark.LiveCapture(interface=self.interface, display_filter=self.display_filter)

    def update_dhcp_servers(self, packet: Packet) -> None:
        if packet.dhcp.option_dhcp == "2":
            ip = packet.dhcp.option_dhcp_server_id
            mac = packet.eth.src
            subnet = packet.dhcp.option_subnet_mask
            default_gateway = "metti qualcosa"
            dns_server = "google.cazz"

            if len(self.dhcp_servers) > 0:
                found = False
                for server in self.dhcp_servers:
                    if server.mac == mac:
                        server.restore_no_response_count()
                        found = True
                if not found:
                    self.add_new_dhcp_server(ip, mac, subnet, default_gateway, dns_server)
            else:
                self.add_new_dhcp_server(ip, mac, subnet, default_gateway, dns_server)

    def add_new_dhcp_server(self, ip: str, mac: str, subnet: str, default_gateway: str, dns_server: str) -> None:
        new_dhcp_server = DHCPServer(ip, mac, subnet, default_gateway, dns_server)
        self.dhcp_servers.append(new_dhcp_server)
        message = f"New DHCP Server discovered!\n\t\t {new_dhcp_server.get_info()}"
        self.safe_print.print(message, color.RED)

    def increase_counter(self) -> None:
        for server in self.dhcp_servers:
            if server.no_response_count > 3:
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
                message += f"\t{server.get_info()}\n"

        message += "#############################"
        self.safe_print.print(message, color.GREEN)

    def send_dhcp_discover(self) -> None:
        self.safe_print.print("sending DHCP discover...", color.YELLOW)
        local_mac = get_if_hwaddr(self.interface)
        fam, local_raw_mac = get_if_raw_hwaddr(self.interface)
        broadcast_mac = "ff:ff:ff:ff:ff:ff"
        source_ip = "0.0.0.0"
        dest_ip = "255.255.255.255"

        dhcp_discover = Ether(src=local_mac, dst=broadcast_mac) / IP(src=source_ip, dst=dest_ip) / UDP(
            dport=67, sport=68) / BOOTP(chaddr=local_raw_mac) / DHCP(options=[("message-type", "discover"), "end"])
        sendp(dhcp_discover, iface=self.interface, count=15, inter=0.5, verbose=False)
        time.sleep(self.timeout)

    def __send_dhcp_discover_threaded(self) -> None:
        while True:
            self.send_dhcp_discover()

    def callback(self, packet: Packet) -> None:
        if packet is not None:
            self.update_dhcp_servers(packet)
            self.print_status()
            time.sleep(self.timeout)

    def run(self) -> None:
        discover_sender = Thread(target=self.__send_dhcp_discover_threaded)
        discover_sender.start()
        self.capture.apply_on_packets(callback=self.callback)
