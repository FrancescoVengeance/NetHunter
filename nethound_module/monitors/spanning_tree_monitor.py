from threading import Thread
from nethound_module.network_elements.switch import Switch, Port
from pyshark.packet.packet import Packet
from nethound_module.safe_print import SafePrint


class SpanningTreeMonitor(Thread):
    def __init__(self, safe_print: SafePrint):
        super().__init__()
        self.switches_table: [Switch] = []
        self.switch_baseline: dict = {}
        self.waiting_timer: int = 0
        self.safe_print = safe_print

    def update_switches_table(self, packet: Packet) -> None:
        if packet.highest_layer.upper() == "STP":
            if self.waiting_timer < (int(packet.stp.forward) + int(packet.stp.max_age)):
                self.waiting_timer = (int(packet.stp.forward) + int(packet.stp.max_age))
            if "type" in packet.eth.field_names and packet.eth.type == "0x00008100":
                found = False
                for switch in self.switches_table:
                    if packet.eth.src == packet.stp.bridge_hw and packet.stp.port != "0x00008001":
                        sender_mac = self.calculate_sender_mac(packet.eth.src, packet.stp.port)
                    else:
                        sender_mac = packet.eth.src

                    vlan_id = packet.vlan.id
                    if switch.contains(sender_mac):
                        found = True
                        switch.get_port(sender_mac).trunk = True
                        switch.set_designated_port(sender_mac, vlan_id, override=True, priority=packet.stp.root_prio,
                                                   b_id=packet.stp.root_hw, initialization=True)
                if not found:
                    self.add_new_switch(packet)
            else:
                found = True
                for switch in self.switches_table:
                    if packet.eth.src == packet.stp.bridge_hw and packet.stp.port != "0x00008001":
                        sender_mac = self.calculate_sender_mac(packet.eth.src, packet.stp.port)
                    else:
                        sender_mac = packet.eth.src
                    if packet.stp.bridge_ext == "0" and packet.stp.root_ext == "0":
                        vlan_id = 0
                        if switch.contains(sender_mac):
                            port = switch.get_port(sender_mac)
                            if not port.trunk and len(port.get_vlan()) > 0:
                                vlan_id = port.get_vlan()[0]
                    else:
                        vlan_id = packet.stp.root_ext if packet.stp.bridge_ext == "0" else packet.stp.bridge_ext

                    if switch.bridge_id == packet.stp.bridge_hw:
                        switch.set_designated_port(sender_mac, vlan_id, override=True, priority=packet.stp.root_prio,
                                                   b_id=packet.stp.root_hw, initialization=True)
                        found = True
                if not found:
                    self.add_new_switch(packet)
        elif packet.highest_layer.upper() == "DTP":
            self.discover_switch_spoofing(packet)
            if packet.dtp.tas == "0x00000001" or packet.dtp.tos == "0x00000001":
                for switch in self.switches_table:
                    sender_mac = packet.eth.src
                    if switch.contains(sender_mac):
                        switch.get_port(sender_mac).trunk = True
                        self.safe_print.print(f"Port {sender_mac} is trunk")

    def add_new_switch(self, packet: Packet):
        switch = Switch(packet.stp.bridge_hw, None, None, None, None)
        if 'type' in packet.eth.field_names and packet.eth.type == '0x00008100':
            vlan_id = packet.vlan.id
        else:
            vlan_id = packet.stp.root_ext if packet.stp.bridge_ext == '0' else packet.stp.bridge_ext
        if packet.eth.src == packet.stp.bridge_hw and packet.stp.port != '0x00008001':
            sender_mac = self.calculate_sender_mac(packet.eth.src, packet.stp.port)
        else:
            sender_mac = packet.eth.src
        bridge_id = packet.stp.bridge_hw
        priority = packet.stp.bridge_prio
        port = Port(sender_mac, sender_mac)
        switch.add_ports(port)
        switch.set_designated_port(port.mac, vlan_id, priority=priority,
                                   b_id=bridge_id, initialization=True)
        switch.set_spanning_tree_root_id(vlan_id, packet.stp.root_hw)
        self.switches_table.append(switch)

    @staticmethod
    def calculate_sender_mac(src, port_id):
        mac_parts = src.split(':')
        raw_mac = ''
        for part in mac_parts:
            raw_mac += part

        num_mac = hex(int(raw_mac, 16) + (int(port_id, 16)-32768))[2:].zfill(12)
        sender_mac = ''
        for index in range(0, len(num_mac)):
            if index > 0 and (index % 2) == 0:
                sender_mac += ':'
            sender_mac += num_mac[index]

        return str(sender_mac)

    def discover_vlan_hopping(self, packet: Packet):
        if 'type' in packet.eth.field_names and packet.eth.type == '0x00008100':
            if 'etype' in packet.vlan.field_names and packet.vlan.etype == '0x00008100':
                vlans = []
                for layer in packet.layers:
                    if layer.layer_name == 'vlan':
                        vlans.append(layer.id)
                self.safe_print.print(f"[WARNING] Packet with DOUBLE 802.1Q found! send from: {packet.eth.src} "
                                      f"with this vlan tagged: {vlans}")

    def discover_switch_spoofing(self, packet):
        if packet is not None:
            src = packet.eth.src
            if packet.dtp.tat == '0x00000000':
                for switch in self.switches_table:
                    if switch.contains(src) and not switch.get_port(src).negotiation:
                        port_name = switch.get_port(src).name
                        switch.get_port(src).negotiation = True
                        switch.get_port(src).negotiation_rcvd = True
                        msg = "Alert, interface %s on switch %s allow trunk negotiation!" % (port_name, switch.name)
                        message = f"[WARNING] interface {port_name} on switch {switch.name} allows trunk negotiation !"
                        self.safe_print.print(message)
            else:
                for switch in self.switches_table:
                    if switch.contains(src) and switch.get_port(src).negotiation:
                        port_name = switch.get_port(src).name
                        switch.get_port(src).negotiation = False
                        switch.get_port(src).no_negotiation_count = 0
                        message = f"Interface {port_name} on switch {switch.name} no longer allows trunk negotiation"
                        self.safe_print.print(message)

