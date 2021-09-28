from threading import Thread
from network_elements.switch import Switch, Port
from pyshark.packet.packet import Packet
from safe_print import SafePrint
import pyshark


class SpanningTreeMonitor(Thread):
    def __init__(self, safe_print: SafePrint, interface: str):
        super().__init__()
        self.switches_table: [Switch] = []
        self.switch_baseline: dict = {}
        self.waiting_timer: int = 0
        self.safe_print: SafePrint = safe_print
        self.interface: str = interface
        self.initialization: bool = True
        self.display_filter: str = "cdp or lldp or stp or dtp"  # or stp.flags.tc == 1 da inserire in topology changes
        self.capture = pyshark.LiveCapture(interface=self.interface, display_filter=self.display_filter)
        self.connected_switch: dict[str, str] = {}

    def run(self) -> None:
        self.capture.apply_on_packets(callback=self.callback)

    def callback(self, packet: Packet) -> None:
        if self.initialization:
            self.wait_for_initial_information(packet)

        # if net_interface.ssh_no_credential_connection()
        #     self.add_switch(net_interface.take_interfaces())
        #     net_interface.enable_monitor_mode()
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

    def add_switch(self) -> None:
        pass

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
            self.safe_print.print("Waiting for initial configuration...")

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

            self.safe_print.print("Initial configuration done!")
