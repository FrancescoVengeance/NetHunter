import getpass
from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from SSHConnettors import *
import base64
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import pyshark


class NetInterface:

    def __init__(self, interface, password=None):
        self.interface = interface
        self.timeout = 30
        self.switch_ip = None
        self.switch_interface = None
        self.switch_MAC = None
        self.ssh = None
        self.password = password
        self.kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'2048',
                iterations=100000,
                backend=default_backend()
            )

    def wait_for_initial_information(self):
        print("Wait for initial configurations... ")
        capt = pyshark.LiveCapture(interface=self.interface, display_filter="cdp or lldp")
        capt.sniff(packet_count=3, timeout=60)

        if capt:
            for pkt in capt:
                if pkt.highest_layer.upper() == 'CDP':
                    if 'number_of_addresses' in pkt.cdp.field_names and pkt.cdp.number_of_addresses == '1':
                        self.switch_ip = pkt.cdp.nrgyz_ip_address
                    if 'Port'in pkt.cdp.portid:
                        self.switch_interface = pkt.cdp.portid.split('Port: ')[1]
                    else:
                        self.switch_interface = pkt.cdp.portid
                    self.switch_MAC = pkt.eth.src
                if pkt.highest_layer.upper() == 'LLDP':
                    if 'mgn_addr_ip4' in pkt.lldp.field_names:
                        self.switch_ip = pkt.lldp.mgn_addr_ip4
                    if 'chassis_id_mac' in pkt.lldp.field_names:
                        self.switch_MAC = pkt.lldp.chassis_id_mac
                    else:
                        self.switch_MAC = pkt.eth.src
                    self.switch_interface = pkt.lldp.port_id

        # capt.eventloop.close()
        print("initial configurations done!")

    def ssh_connection(self):
        if self.switch_ip is None:
            self.switch_ip = input('switch_ip: ')
        switch_name = input('switch username: ')
        switch_pwd = getpass.getpass('password: ')
        switch_en_pwd = getpass.getpass('enable password: ')

        print("Connecting to SSH...")
        self.ssh = self.get_ssh_module_by_vendor()
        if self.ssh is None:
            return False

        return self.ssh.connect(self.switch_ip, switch_name, switch_pwd, switch_en_pwd, 20)

    def parameterized_ssh_connection(self, switch_mac, switch_ip, switch_name, switch_pwd, switch_en_pwd, switch_interface,
                                     attempts=1):
        print("Connecting to SSH...")
        self.switch_MAC = switch_mac
        self.ssh = self.get_ssh_module_by_vendor(switch_interface)
        if self.ssh is None:
            return False

        return self.ssh.connect(switch_ip, switch_name, switch_pwd, switch_en_pwd, attempts)

    def ssh_no_credential_connection(self):
        if self.switch_ip is not None:
            print("Connecting to SSH...")

            self.ssh = self.get_ssh_module_by_vendor()
            if self.ssh is None:
                return False

            credentials = self.read_credentials()
            index = 0
            (name, pwd, en_pwd) = credentials[index]
            connected = self.ssh.connect(self.switch_ip, name, pwd, en_pwd, 5)

            while index < (len(credentials)-1) and not connected:
                index += 1
                (name, pwd, en_pwd) = credentials[index]
                connected = self.ssh.connect(self.switch_ip, name, pwd, en_pwd, 5)

            return connected

    def get_ssh_module_by_vendor(self, connected_interface=None):
        if connected_interface is None:
            connected_interface = self.switch_interface

        vendor = None
        vendors = self.read_vendors()
        if str(self.switch_MAC[:8]) in vendors:
            vendor = vendors[str(self.switch_MAC[:8])]
        else:
            return None

        if 'Extreme' in vendor:
            return ExtremeSSH(connected_interface, self.timeout, self.switch_MAC)
        if 'Cisco' in vendor:
            return CiscoSSH(connected_interface, self.timeout)

        return None

    def get_ssh_module_by_mac(self, mac: str, connected_interface: str):
        vendor = None
        vendors = self.read_vendors()
        if str(mac[:8]) in vendors:
            vendor = vendors[str(mac[:8])]
        else:
            return None

        if 'Extreme' in vendor:
            return ExtremeSSH(connected_interface, 15, mac)
        if 'Cisco' in vendor:
            return CiscoSSH(connected_interface, 15)

        return None


    def enable_monitor_mode(self):
        if self.ssh is not None:
            self.ssh.enable_monitor_mode()

    def take_interfaces(self):
        if self.ssh is not None:
            return self.ssh.take_interfaces()

    def send_dhcp_discover(self):
        print('sending DHCP discover...')
        local_mac = get_if_hwaddr(self.interface)
        fam, local_mac_raw = get_if_raw_hwaddr(self.interface)
        broad_mac = 'ff:ff:ff:ff:ff:ff'
        source_ip = '0.0.0.0'
        dest_ip = '255.255.255.255'

        dhcp_discover = Ether(src=local_mac, dst=broad_mac) / IP(src=source_ip, dst=dest_ip) / UDP(
            dport=67, sport=68) / BOOTP(chaddr=local_mac_raw) / DHCP(options=[('message-type', 'discover'), 'end'])
        sendp(dhcp_discover, iface=self.interface, count=15, inter=0.5, verbose=False)

    def send_dns_query(self):
        print('sending DNS Query...')
        local_mac = get_if_hwaddr(self.interface)
        broad_mac = 'ff:ff:ff:ff:ff:ff'
        dest_ip = '255.255.255.255'

        dns_request = Ether(src=local_mac, dst=broad_mac) / IP(dst=dest_ip)/UDP(sport=RandShort(), dport=53) / \
                      DNS(rd=1, qd=DNSQR(qname="google.it", qtype="A"))

        sendp(dns_request, iface=self.interface, verbose=False, count=15, inter=0.5)

    def read_credentials(self):
        credentials = list()

        if self.password is not None:
            password = self.password.encode()

            key = base64.urlsafe_b64encode(self.kdf.derive(password))
            fernet = Fernet(key)

            raw_data = open('credentials.naspy')
            data = json.load(raw_data)

            for name in data:
                raw_item = data[name]
                pwd = fernet.decrypt(raw_item[0].encode()).decode()
                en_pwd = fernet.decrypt(raw_item[1].encode()).decode()
                credentials.append((name, pwd, en_pwd))

            return credentials

    @staticmethod
    def read_vendors():
        file = open('mac_vendor.naspy')
        vendors = eval(file.read())
        file.close()
        return vendors
