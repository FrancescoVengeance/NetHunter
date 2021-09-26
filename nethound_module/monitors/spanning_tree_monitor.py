import concurrent
from threading import Thread
from nethound_module.network_elements.switch import Switch, Port
from pyshark.packet.packet import Packet
import copy
from nethound_module.packets_buffer import PacketsBuffer
from nethound_module.safe_print import SafePrint


class SpanningTreeMonitor(Thread):
    def __init__(self, packets_buffer: PacketsBuffer, safe_print: SafePrint):
        super().__init__()
        self.switches_table: [Switch] = []
        self.switch_baseline: dict = {}
        self.waiting_timer: int = 0
        self.safe_print = safe_print
        self.packets_buffer = packets_buffer

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

    def discover_topology_changes(self, my_host_interface, password, packet: Packet) -> None:
        switch_ip, switch_mac = self.get_initial_information(packet)
        # net_interface.ssh_no_credential_connection()

        for switch in self.switches_table:
            bridge_id_min = dict()
            root_port = dict()
            blocked_port = dict()
            if switch.contains(switch_mac):
                self.switch_baseline = copy.deepcopy(switch.spanning_tree_instances)
                self.discover_vlan_hopping(packet)
                self.spanning_tree_check(packet)

                if switch.connected_interface is not None:
                    pass
                    # net_interface.ssh.enable_monitor_mode_on_interface_range(switch.get_interfaces())

                for vlan_id in switch.get_vlans():
                    bridge_id_min[vlan_id] = (60000, None)  # Priority, Mac
                    root_port[vlan_id] = None
                    blocked_port[vlan_id] = None

                if switch.connected_interface is not None:
                    for port in self.take_blocked_port_from_baseline():
                        print("Waiting...")
                        time.sleep(net_interface.timeout)
                        net_interface.parameterized_ssh_connection(switch.bridge_id, switch.ip, switch.name, switch.password,
                                                                   switch.en_password, switch.connected_interface, 20)
                        print('start sniffing on %s (%s)...' % (port.name, port.MAC))
                        port_capture = pyshark.LiveCapture(interface=net_interface.interface,
                                                           display_filter="stp")
                        net_interface.ssh.enable_monitor_mode_on_specific_port(port.name)
                        if port.trunk:
                            rcvd_pkt = dict()
                            to_not_remove = list()
                            port_capture.sniff(packet_count=len(switch.get_vlans()), timeout=10)
                            if port_capture:
                                for pkt in port_capture:
                                    vlan_id = pkt.stp.root_ext if pkt.stp.bridge_ext == '0' else pkt.stp.bridge_ext
                                    if vlan_id == 0 and 'type' in pkt.eth.field_names and pkt.eth.type == '0x00008100':
                                        vlan_id = pkt.vlan.id

                                    if vlan_id not in port.pvlan_status:
                                        switch.set_blocked_port(port.MAC, pkt.stp.bridge_ext,
                                                                priority=pkt.stp.root_prio, b_id=pkt.stp.root_hw, initialization=True)
                                    elif pkt.stp.bridge_hw == switch.bridge_id:
                                        to_not_remove.append(vlan_id)
                                    if vlan_id not in rcvd_pkt and pkt.stp.bridge_hw != switch.bridge_id:
                                        rcvd_pkt[vlan_id] = pkt

                                for vlan in port.get_vlan():
                                    if vlan not in bridge_id_min:
                                        bridge_id_min[vlan] = (60000, None)
                                    if vlan not in root_port:
                                        root_port[vlan] = None
                                    if vlan not in blocked_port:
                                        blocked_port[vlan] = None
                                    if vlan in rcvd_pkt:
                                        bridge_id_min[vlan], root_port[vlan], blocked_port[vlan] = self.get_min_bridge_id(rcvd_pkt[vlan], bridge_id_min[vlan],
                                                                                                                          port.MAC, root_port[vlan], blocked_port[vlan])
                                    elif vlan not in to_not_remove:
                                        switch.get_port(port.MAC).remove_vlan(vlan, self.log)
                                        switch.remove_port_from_stp(vlan, switch.get_port(port.MAC))
                        else:
                            port_capture.sniff(packet_count=1, timeout=10)
                            if port_capture:
                                pkt = port_capture[0]
                                vlan = pkt.stp.root_ext if pkt.stp.bridge_ext == '0' else pkt.stp.bridge_ext
                                if port.MAC != pkt.eth.src:
                                    if vlan not in port.pvlan_status:
                                        switch.set_blocked_port(port.MAC, vlan,
                                                                priority=pkt.stp.root_prio, b_id=pkt.stp.root_hw)
                                    bridge_id_min[vlan], root_port[vlan], blocked_port[vlan] = self.get_min_bridge_id(pkt, bridge_id_min[vlan], port.MAC,
                                                                                                                      root_port[vlan], blocked_port[vlan])
                        port_capture.close()
            if switch.connected_interface is not None:
                for vlan_id in switch.get_vlans():
                    if vlan_id in root_port and root_port[vlan_id] is not None:
                        for port in switch.ports:
                            if port.MAC == root_port[vlan_id]:
                                if port.pvlan_status[vlan_id] != "Root":
                                    msg = "Port %s has switch his state on vlan %s - From %s to Root" % (port.name,
                                                                                                         vlan_id,
                                                                                                         port.pvlan_status[vlan_id])
                                    print(msg)
                                    self.print_to_log(msg)
                                    switch.increase_port_tc_counter(vlan_id, port.MAC)
                                    switch.set_root_port(root_port[vlan_id], vlan_id, override=True)
                            else:
                                if blocked_port[vlan_id] is not None and port.MAC == blocked_port[vlan_id]:
                                    if port.pvlan_status[vlan_id] != "Blocked":
                                        msg = "Port %s has switch his state on vlan %s - From %s to Blocked" % (port.name, vlan_id, port.pvlan_status[vlan_id])
                                        print(msg)
                                        self.print_to_log(msg)
                                        switch.increase_port_tc_counter(vlan_id, port.MAC)
                                    switch.set_blocked_port(blocked_port[vlan_id], vlan_id, override=True)
                                else:
                                    if vlan_id in port.pvlan_status and self.port_in_baseline(port, vlan_id):
                                        port.remove_vlan(vlan_id, self.log)
                                        switch.remove_port_from_stp(vlan_id, port)
            for port in switch.ports:
                if port.negotiation:
                    if port.no_nego_count >= 3:
                        port.negotiation = False
                        port.no_nego_count = 0
                        msg = "Interface %s on switch %s no longer allow trunk negotiation!" % (port.name, switch.name)
                        print(msg)
                        self.print_to_log(msg)
                    elif not port.negotiation_rcvd:
                        port.no_nego_count += 1
                    else:
                        port.no_nego_count = 0
                        port.negotiation_rcvd = False

    # da richiamare all'inizio di tutto
    def get_initial_information(self, packet: Packet):
        switch_ip = None
        switch_mac = None
        if packet.highest_layer.upper() == "CDP":
            if "number_of_addresses" in packet.cdp.field_names and packet.cdp.number_of_addresses == "1":
                switch_ip = packet.cdp.nrgyz_ip_address
            if "Port" in packet.cdp.portid:
                pass
                # self.switch_interface = packet.cdp.portid.split("Port: ")[1]
            else:
                pass
                # self.switch_interface = packet.cdp.portid
            switch_mac = packet.eth.src
        if packet.highest_layer.upper() == 'LLDP':
            if 'mgn_addr_ip4' in packet.lldp.field_names:
                switch_ip = packet.lldp.mgn_addr_ip4
            if 'chassis_id_mac' in packet.lldp.field_names:
                switch_mac = packet.lldp.chassis_id_mac
            else:
                switch_mac = packet.eth.src
            # self.switch_interface = packet.lldp.port_id

        return switch_ip, switch_mac

    def spanning_tree_check(self, packet: Packet) -> None:
        if packet.highest_layer.upper() == "STP":
            if packet.eth.src == packet.stp.bridge_hw and packet.stp.port != '0x00008001':
                sender_mac = self.calculate_sender_mac(packet.eth.src, packet.stp.port)
            else:
                sender_mac = packet.eth.src
            packet_bridge_id = packet.eth.src
            switch = self.get_switch(packet_bridge_id)
            if switch is not None:
                port = switch.get_port(sender_mac)
                packet_vlan_id = packet.stp.root_ext if packet.stp.bridge_ext == "0" else packet.stp.bridge_ext
                packet_root_id = packet.stp.root_hw
                if (packet_vlan_id == 0 or packet_root_id == 0) and "type" in packet.eth.field_names and packet.eth.type == "0x00008100":
                    packet_vlan_id = packet.vlan.id

                if packet_vlan_id in self.switch_baseline:
                    if packet_bridge_id == self.switch_baseline[packet_vlan_id].bridge_id:
                        if self.port_in_baseline(port, packet_vlan_id):
                            old_priority = self.switch_baseline[packet_vlan_id].priority
                            topology_change = False
                            if int(packet_vlan_id) + int(packet.stp.root_prio) != old_priority:
                                topology_change = True
                                switch.set_spanning_tree_priority(packet_vlan_id, packet.stp.root_prio)
                                self.switch_baseline[packet_vlan_id].priority = int(packet_vlan_id) + int(packet.stp.root_prio)
                                message = f"Bridge {packet_bridge_id} priority on vlan {packet_vlan_id} is changed" \
                                          f" from {old_priority} to {int(packet_vlan_id) + int(packet.stp.root_prio)}"
                                self.safe_print.print(message)

                            old_root_bridge = self.switch_baseline[packet_vlan_id].root_bridge_id
                            if packet_root_id != old_root_bridge:
                                topology_change = True
                                switch.set_spanning_tree_root_id(packet_vlan_id, packet_root_id)
                                self.switch_baseline[packet_vlan_id].root_bridge_id = packet_root_id
                                message = f"[WARNING] Root bridge change! the new root bridge of vlan {packet_vlan_id} " \
                                          f"is {packet_root_id}"
                                self.safe_print.print(message)
                            if packet_vlan_id in port.pvlan_status:
                                port_status = port.pvlan_status[packet_vlan_id]
                                if port_status != "Designated":
                                    switch.set_designated_port(sender_mac, packet_vlan_id, override=True)
                                    switch.increase_port_tc_counter(packet_vlan_id, sender_mac)
                                    message = f"Port {port.name} on vlan {packet_vlan_id} has switched its state from " \
                                              f"{port_status} to designated"
                                    self.safe_print.print(message)
                                for bport in self.switch_baseline[packet_vlan_id].ports:
                                    if port.mac == bport.mac:
                                        self.switch_baseline[packet_vlan_id].ports.remove(bport)

                            if topology_change:
                                switch.increase_tc_counter(packet_vlan_id)
                        elif packet_vlan_id not in port.pvlan_status:
                            switch.set_designated_port(sender_mac, packet_vlan_id, priority=packet.stp.root_prio,
                                                       b_id=packet_root_id, initialization=True)
                            self.add_port_to_baseline(port.mac, packet_vlan_id)
                            message = f"New vlan {packet_vlan_id} has added at this trunk port {port.name}"
                            self.safe_print.print(message)

                elif packet_vlan_id not in port.pvlan_status:
                    switch.set_designated_port(sender_mac, packet_vlan_id, priority=packet.stp.root_prio,
                                               b_id=packet_root_id, initialization=True)
                    self.add_port_to_baseline(port.mac, packet_vlan_id)
                    message = f"New vlan {packet_vlan_id} has added at this trunk port {port.name}"
                    self.safe_print.print(message)
        else:
            sender_mac = packet.eth.src
            # new trunk port discovered
            if packet.highest_layer.upper() == "DTP":
                self.discover_switch_spoofing(packet)
                if packet.dtp.tas == "0x00000001" or packet.dtp.tos == "0x00000001":
                    for switch in self.switches_table:
                        if switch.contains(sender_mac) and not switch.get_port(sender_mac).trunk:
                            message = f"[WARNING] Port {sender_mac} is not trunk"
                            self.safe_print.print(message)
                            switch.get_port(sender_mac).trunk = True
                            for vlan in self.switch_baseline:
                                for port in self.switch_baseline[vlan].ports:
                                    if port.mac == sender_mac:
                                        port.trunk = True
