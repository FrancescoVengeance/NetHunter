from pathlib import Path
from threading import Thread
from network_elements.switch import Switch, Port
from pyshark.packet.packet import Packet
from safe_print import SafePrint
import pyshark
from NetInterface import NetInterface
from naspy.Naspy import decryptDB


class SpanningTreeMonitor(Thread):
    def __init__(self, safe_print: SafePrint, interface: str):
        super().__init__()
        self.BASE_DIR = Path(__file__).resolve().parent.parent.parent
        self.switches_table: [Switch] = []
        self.switch_baseline: dict = {}
        self.waiting_timer: int = 0
        self.safe_print: SafePrint = safe_print
        self.interface: str = interface
        self.initialization: bool = True
        self.display_filter: str = "cdp or lldp or stp or dtp"  # or stp.flags.tc == 1 da inserire in topology changes
        self.capture = pyshark.LiveCapture(interface=self.interface, display_filter=self.display_filter)
        self.connected_switch: dict[str, str] = {}
        self.start_message = "#### STP MONITOR ####\n"
        self.end_message = "#####################"

    def run(self) -> None:
        self.capture.apply_on_packets(callback=self.callback)

    def callback(self, packet: Packet) -> None:
        if self.initialization:
            self.wait_for_initial_information(packet)

        connected, ssh_connector = self.connect_switch()
        if connected and ssh_connector is not None:
            self.add_switch(ssh_connector.take_interfaces())
            message = self.start_message + "Enabling monitor mode\n" + self.end_message
            self.safe_print.print(message)
            ssh_connector.enable_monitor_mode()

        self.update_switches_table(packet)
        self.discover_vlan_hopping(packet)
        self.set_connected_interface_status()
        self.find_root_port()
        self.discover_topology_changes()
        self.print_status()

    def update_switches_table(self, packet: Packet) -> None:
        pass

    def discover_vlan_hopping(self, packet: Packet) -> None:
        pass

    def add_switch(self, switch) -> None:
        if switch not in self.switches_table:
            self.switches_table.append(switch)

    def set_connected_interface_status(self) -> None:
        pass

    def find_root_port(self) -> None:
        pass

    def print_status(self) -> None:
        pass

    def discover_topology_changes(self) -> None:
        pass

    def wait_for_initial_information(self, packet: Packet) -> None:
        if self.initialization and packet.highest_layer.upper() in ("CDP", "LLDP"):
            message = self.start_message + "Waiting for initial configuration\n" + self.end_message
            self.safe_print.print(message)

            if packet.highest_layer.upper() == "CDP":
                self.connected_switch["mac"] = packet.eth.src
                self.initialization = False
                if "number_of_addresses" in packet.cdp.field_names and packet.cdp.number_of_addresses == '1':
                    self.connected_switch["ip"] = packet.cdp.nrgyz_ip_address
                if "Port" in packet.cdp.portid:
                    self.connected_switch["interface"] = packet.cdp.portid.split('Port: ')[1]
                else:
                    self.connected_switch["interface"] = packet.cdp.portid
            if packet.highest_layer.upper() == "LLDP":
                self.connected_switch["interface"] = packet.lldp.port_id
                self.initialization = False
                if 'mgn_addr_ip4' in packet.lldp.field_names:
                    self.connected_switch["ip"] = packet.lldp.mgn_addr_ip4
                if 'chassis_id_mac' in packet.lldp.field_names:
                    self.connected_switch["mac"] = packet.lldp.chassis_id_mac
                else:
                    self.connected_switch["mac"] = packet.eth.src

            message = self.start_message + "\n" + "Initial configuration done!\n" + self.end_message
            self.safe_print.print(message)

    def connect_switch(self) -> tuple:
        if "ip" in self.connected_switch and self.connected_switch["ip"] is not None:
            message = self.start_message + f"Connecting to {self.connected_switch['ip']}\n" + self.end_message
            self.safe_print.print(message)

            net_interface = NetInterface(self.interface)
            ssh_connector = net_interface.get_ssh_module_by_mac(self.connected_switch["mac"], self.connected_switch["interface"])
            if ssh_connector is None:
                return False, None

            credentials = decryptDB(self.BASE_DIR)
            switch_ip = self.connected_switch["ip"]
            connected = ssh_connector.connect(switch_ip, credentials[switch_ip]["username"], credentials[switch_ip]["password"],
                                              credentials[switch_ip]["enable"], 5)

            return connected, ssh_connector
