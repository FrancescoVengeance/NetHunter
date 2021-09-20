from threading import Thread
from time import sleep
from nethound_module.packets_queue import PacketsQueue
from nethound_module.safe_print import SafePrint
from nethound_module.network_elements.dns_server import DNServer
from pyshark.packet.packet import Packet


class DNSMonitor(Thread):
    def __init__(self, interface: str, packets: PacketsQueue, safe_print: SafePrint):
        super().__init__()
        self.interface: str = interface
        self.packets: PacketsQueue = packets
        self.safe_print: SafePrint = safe_print
        self.dns_servers: [DNServer] = []

    def update_dns_servers(self, packet: Packet) -> None:
        if packet.dns.flags_response == "1":
            ip = packet.ip.src
            mac = packet.eth.src

            if len(self.dns_servers) > 0:
                found = False
                for server in self.dns_servers:
                    if server.mac == mac:
                        server.restore_no_response_count()
                        found = True
                if not found:
                    self.add_new_dns_server(ip, mac)
            else:
                self.add_new_dns_server(ip, mac)

    def add_new_dns_server(self, ip: str, mac: str) -> None:
        server = DNServer(ip, mac, "home.it")
        self.dns_servers.append(server)
        message = f"New DHCP Server discovered!\n\t\t IP: {ip} | MAC: {mac} | Domain: {server.domain}"
        self.safe_print(message)

    def increase_counter(self) -> None:
        for server in self.dns_servers:
            if server.no_response_count > 3:
                self.safe_print(f"DNS server [{server.ip}] is no longer avaible")
                self.dns_servers.remove(server)
            server.increase_no_response_count()

    def print_status(self) -> None:
        message = "######## DNS STATUS ########"
        if len(self.dns_servers) == 0:
            message += "\n\t No DNS Servers found! \t\t\n"
        else:
            message += "\n"
            for server in self.dns_servers:
                message += f"\t{server.get_info()}\n"

        message += "#############################"
        self.safe_print.print(message)


