from threading import Thread
from time import sleep
from packets_buffer import PacketsBuffer
from safe_print import SafePrint
from network_elements.dns_server import DNServer
from pyshark.packet.packet import Packet
from scapy.arch import get_if_hwaddr
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sendp
from scapy.volatile import RandShort


class DNSMonitor(Thread):
    def __init__(self, interface: str, packets: PacketsBuffer, safe_print: SafePrint):
        super().__init__()
        self.interface: str = interface
        self.packets: PacketsBuffer = packets
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
        # self.safe_print(message)
        print(message)

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
        # self.safe_print.print(message)
        print(message)

    def send_dns_query(self) -> None:
        self.safe_print.print("sending DNS query...")
        mac = get_if_hwaddr(self.interface)
        broadcast = "ff:ff:ff:ff:ff:ff"
        destination_ip = "255.255.255.255"

        dns_query = Ether(src=mac, dst=broadcast) / IP(dst=destination_ip) / UDP(sport=RandShort(), dport=53) / \
            DNS(rd=1, qd=DNSQR(qname="google.it", qtype="A"))

        sendp(dns_query, iface=self.interface, verbose=False, count=15, inter=0.5)

    def run(self) -> None:
        stop = False
        while not stop:
            try:
                self.send_dns_query()
                sleep(1)
                # packet = self.packets.pop("DNS")
                # count = 0
                # while (packet is not None and packet.dns.flags_response != "1") or count > 6:
                #     packet = self.packets.pop("DNS")
                #     count += 1
                packet = self.packets.pop("DNS")
                if packet is not None:
                    self.update_dns_servers(packet)
                self.print_status()
                sleep(2)
            except KeyboardInterrupt:
                stop = True
