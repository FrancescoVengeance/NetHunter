from builtins import print

from NetworkElements import *
from NetInterface import *
from LogSender import LogSender
import time
import copy
import concurrent


class RogueDHCPMonitor:

    def __init__(self, log):
        self.dhcp_servers = list()
        self.log = log

    def update_dhcp_servers(self, pkt):
        if pkt.bootp.option_dhcp == '2':
            pkt_ip = pkt.bootp.option_dhcp_server_id
            pkt_mac = pkt.eth.src

            if 'option_subnet_mask' in pkt.bootp.field_names:
                subnet = pkt.bootp.option_subnet_mask
            else:
                subnet = '0.0.0.0'

            if len(self.dhcp_servers) > 0:
                found = False
                for dhcp_server in self.dhcp_servers:
                    if dhcp_server.equals(pkt_mac):
                        dhcp_server.restore_response_count()
                        found = True
                if not found:
                    self.add_new_dhcp_server(pkt_ip, pkt_mac, subnet)
            else:
                self.add_new_dhcp_server(pkt_ip, pkt_mac, subnet)

    def add_new_dhcp_server(self, pkt_ip, pkt_mac, subnet):
        new_dhcp_server = DHCPServer(pkt_ip, pkt_mac, subnet)
        self.dhcp_servers.append(new_dhcp_server)
        print("New DHCP Server discovered")
        self.print_to_log('New DHCP Server discovered')
        self.print_to_log(new_dhcp_server.print_info())

    def increase_counter(self):
        for dhcp_server in self.dhcp_servers:
            if dhcp_server.no_response_count >= 3:
                print("DHCP Server %s is no longer available!" % dhcp_server.ip_address)
                self.print_to_log("DHCP Server %s is no longer available!" % dhcp_server.ip_address)
                self.dhcp_servers.remove(dhcp_server)
            dhcp_server.increase_response_count()

    def print_dhcp_servers(self):
        if len(self.dhcp_servers) > 0:
            print("DHCP Servers on the network:")
            self.print_to_log('DHCP Servers on the network:')
            for dhcp_server in self.dhcp_servers:
                self.print_to_log(dhcp_server.print_info())
        else:
            print('No DHCP Servers found!')
            self.print_to_log('No DHCP Servers found!')

    def print_to_log(self, msg):
        if self.log.closed:
            self.log = open('log.naspy', 'a')
        self.log.write('%s - %s \n' % (datetime.now().strftime("%H:%M:%S"), msg))


class RogueDNSMonitor:

    def __init__(self, log):
        self.dns_servers = list()
        self.log = log

    def update_dns_servers(self, pkt):
        if pkt.dns.flags_response == '1':
            server_ip = pkt.ip.src
            server_mac = pkt.eth.src

            if len(self.dns_servers) > 0:
                found = False
                for dns_server in self.dns_servers:
                    if dns_server.equals(server_mac):
                        dns_server.restore_response_count()
                        found = True
                if not found:
                    self.add_new_dns_server(server_ip, server_mac)
            else:
                self.add_new_dns_server(server_ip, server_mac)

    def add_new_dns_server(self, server_ip, server_mac):
        new_dns_server = DNSServer(server_ip, server_mac)
        self.dns_servers.append(new_dns_server)
        print("New DNS Server Discovered")
        self.print_to_log('New DNS Server discovered')
        self.print_to_log(new_dns_server.print_info())

    def increase_counter(self):
        for dns_server in self.dns_servers:
            if dns_server.no_response_count >= 3:
                print("DNS Server %s is no longer available!" % dns_server.ip_address)
                self.print_to_log("DNS Server %s is no longer available!" % dns_server.ip_address)
                self.dns_servers.remove(dns_server)
            else:
                dns_server.increase_response_count()

    def print_dns_servers(self):
        if len(self.dns_servers) > 0:
            print("DNS Servers on the network:")
            for dns_server in self.dns_servers:
                self.print_to_log(dns_server.print_info())
        else:
            print("No DNS Servers found!")
            self.print_to_log('No DNS Servers found!')

    def print_to_log(self, msg):
        if self.log.closed:
            self.log = open('log.naspy', 'a')
        self.log.write('%s - %s \n' % (datetime.now().strftime("%H:%M:%S"), msg))


class ArpMonitor:

    def __init__(self, log):
        self.ip_arp_table = dict()
        self.mac_arp_table = dict()
        self.log = log

    def update_arp_table(self, pkt, sender_port=None, target_port=None):
        sender_mac = pkt.arp.src_hw_mac
        sender_ip = pkt.arp.src_proto_ipv4
        target_mac = pkt.arp.dst_hw_mac
        target_ip = pkt.arp.dst_proto_ipv4

        sender_vlan_id = 1
        target_vlan_id = 1

        if 'type' in pkt.eth.field_names and pkt.eth.type == '0x00008100':
            sender_vlan_id = pkt.vlan.id
            target_vlan_id = pkt.vlan.id
        else:
            if sender_port is not None:
                if not sender_port.trunk:
                    sender_vlan_id = sender_port.pvlan_status[0]

            if target_port is not None:
                if not target_port.trunk:
                    target_vlan_id = target_port.pvlan_status[0]

        if target_mac != '00:00:00:00:00:00' and target_mac != 'ff:ff:ff:ff:ff:ff' and target_ip != '0.0.0.0':
            self.add_entry(target_ip, target_mac, target_vlan_id)

        if sender_mac != '00:00:00:00:00:00' and sender_mac != 'ff:ff:ff:ff:ff:ff':
            self.add_entry(sender_ip, sender_mac, sender_vlan_id)

    def add_entry(self, ip, mac, vlan_id):
        if ip in self.ip_arp_table:
            if not ((mac, vlan_id) in self.ip_arp_table[ip]):
                self.ip_arp_table[ip].append((mac, vlan_id))
                if len(self.ip_arp_table[ip]) > 1:
                    self.check_ip_duplicate()
        else:
            self.ip_arp_table[ip] = list()
            self.ip_arp_table[ip].append((mac, vlan_id))

        if mac in self.mac_arp_table:
            if not ((ip, vlan_id) in self.mac_arp_table[mac]):
                self.mac_arp_table[mac].append((ip, vlan_id))
                if len(self.mac_arp_table[mac]) > 1:
                    self.check_mac_duplicate()
        else:
            self.mac_arp_table[mac] = list()
            self.mac_arp_table[mac].append((ip, vlan_id))

    def check_ip_duplicate(self):
        macs = dict()
        for ip in self.ip_arp_table:
            for pair in self.ip_arp_table[ip]:
                for pair2 in self.ip_arp_table[ip]:
                    if pair[0] != pair2[0] and pair[1] == pair2[1]:
                        if ip in macs:
                            if pair not in macs[ip]:
                                macs[ip].append(pair)
                            if pair2 not in macs[ip]:
                                macs[ip].append(pair2)
                        else:
                            macs[ip] = list()
                            macs[ip].append(pair)
                            macs[ip].append(pair2)

        for ip in macs:
            if len(macs[ip]) > 1:
                msg = "Conflict Found, duplicate IP address: %s with this MACs: %s" % (ip, str(macs[ip])[1:-1])
                self.send_alert_email(msg)
                self.print_to_log(msg)
                print(msg)

    def check_mac_duplicate(self):
        ips = dict()
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

        for mac in ips:
            if len(ips[mac]) > 1:
                msg = "Conflict Found, duplicate MAC address: %s with this IPs: %s" % (mac, str(ips[mac])[1:-1])
                self.send_alert_email(msg)
                self.print_to_log(msg)
                print(msg)

    def send_alert_email(self, msg):
        sender = LogSender()
        sender.send('%s - %s' % (datetime.now().strftime('%H:%M:%S'), msg),
                    'Alert, security issue detected!', attachment=self.get_ip_arp_table_string(), att_type=
                    'text')

    def print_ip_arp_table(self):
        print("Arp Table:")
        self.print_to_log("%s - Arp Table:" % datetime.now().strftime("%H:%M:%S"))
        for ip in self.ip_arp_table:
            msg = "IP %s - MAC: %s" % (ip, str(self.ip_arp_table[ip])[1:-1])
            self.print_to_log(msg)
            print(msg)

    def get_ip_arp_table_string(self):
        msg = "Arp Table:"
        for ip in self.ip_arp_table:
            msg += "IP %s - MAC: %s" % (ip, str(self.ip_arp_table[ip])[1:-1])
        return msg

    def print_mac_arp_table(self):
        for mac in self.mac_arp_table:
            print("MAC: %s - IP: %s" % (mac, str(self.mac_arp_table[mac])[1:-1]))

    def print_to_log(self, msg):
        if self.log.closed:
            self.log = open('log.naspy', 'a')
        self.log.write('%s - %s \n' % (datetime.now().strftime("%H:%M:%S"), msg))


class STPMonitor:

    def __init__(self, log):
        self.switches_table = list()
        self.switch_baseline = dict()
        self.waiting_timer = 0
        self.log = log

    def update_switches_table(self, pkt):
        if pkt.highest_layer.upper() == 'STP':
            if self.waiting_timer < (int(pkt.stp.forward) + int(pkt.stp.max_age)):
                self.waiting_timer = (int(pkt.stp.forward) + int(pkt.stp.max_age))

            if 'type' in pkt.eth.field_names and pkt.eth.type == '0x00008100':
                found = False
                for switch in self.switches_table:
                    if pkt.eth.src == pkt.stp.bridge_hw and pkt.stp.port != '0x00008001':
                        sender_mac = self.calculate_sender_mac(pkt.eth.src, pkt.stp.port)
                    else:
                        sender_mac = pkt.eth.src

                    vlan_id = pkt.vlan.id
                    if switch.contains(sender_mac):
                        found = True
                        switch.get_port(sender_mac).trunk = True
                        switch.set_designated_port(sender_mac, vlan_id, override=True,
                                                   priority=pkt.stp.root_prio, b_id=pkt.stp.root_hw, initialization=True)

                if not found:
                    self.add_new_switch(pkt)
            else:
                found = False
                for switch in self.switches_table:
                    if pkt.eth.src == pkt.stp.bridge_hw and pkt.stp.port != '0x00008001':
                        sender_mac = self.calculate_sender_mac(pkt.eth.src, pkt.stp.port)
                    else:
                        sender_mac = pkt.eth.src

                    if pkt.stp.bridge_ext == '0' and pkt.stp.root_ext == '0':
                        vlan_id = 0
                        if switch.contains(sender_mac):
                            port = switch.get_port(sender_mac)
                            if not port.trunk and len(port.get_vlan()) > 0:
                                vlan_id = port.get_vlan()[0]
                    else:
                        vlan_id = pkt.stp.root_ext if pkt.stp.bridge_ext == '0' else pkt.stp.bridge_ext

                    if switch.bridge_id == pkt.stp.bridge_hw:
                        switch.set_designated_port(sender_mac, vlan_id, override=True, priority=pkt.stp.root_prio,
                                                   b_id=pkt.stp.root_hw, initialization=True)
                        found = True
                    else:
                        if switch.bridge_id is None and switch.contains(sender_mac):
                            switch.bridge_id = pkt.stp.bridge_hw
                            switch.set_designated_port(sender_mac, vlan_id, override=True, priority=pkt.stp.root_prio,
                                                       b_id=pkt.stp.root_hw, initialization=True)
                            found = True

                if not found:
                    self.add_new_switch(pkt)

        else:
            if pkt.highest_layer.upper() == 'DTP':
                self.discover_switch_spoofing(pkt)
                if pkt.dtp.tas == '0x00000001' or pkt.dtp.tos == '0x00000001':
                    for switch in self.switches_table:
                        sender_mac = pkt.eth.src

                        if switch.contains(sender_mac):
                            print("port %s is trunk" % sender_mac)
                            self.print_to_log("port %s is trunk" % sender_mac)
                            switch.get_port(sender_mac).trunk = True

    def add_new_switch(self, pkt):
        switch = Switch(pkt.stp.bridge_hw, None, None, None, None)
        if 'type' in pkt.eth.field_names and pkt.eth.type == '0x00008100':
            vlan_id = pkt.vlan.id
        else:
            vlan_id = pkt.stp.root_ext if pkt.stp.bridge_ext == '0' else pkt.stp.bridge_ext
        if pkt.eth.src == pkt.stp.bridge_hw and pkt.stp.port != '0x00008001':
            sender_mac = self.calculate_sender_mac(pkt.eth.src, pkt.stp.port)
        else:
            sender_mac = pkt.eth.src
        bridge_id = pkt.stp.bridge_hw
        priority = pkt.stp.bridge_prio
        port = Port(sender_mac, sender_mac)
        switch.add_ports(port)
        switch.set_designated_port(port.MAC, vlan_id, priority=priority,
                                   b_id=bridge_id, initialization=True)
        switch.set_stp_root_id(vlan_id, pkt.stp.root_hw)
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

    @staticmethod
    def discover_vlan_hopping(pkt, log):
        if 'type' in pkt.eth.field_names and pkt.eth.type == '0x00008100':
            if 'etype' in pkt.vlan.field_names and pkt.vlan.etype == '0x00008100':
                vlans = list()
                for layer in pkt.layers:
                    if layer.layer_name == 'vlan':
                        vlans.append(layer.id)
                msg = "Alert, packet with DOUBLE 802.1Q TAGGING found! send from %s with this vlan tagged: %s" % (pkt.eth.src, vlans)
                print(msg)
                sender = LogSender()
                sender.send(msg, 'Double Tagging Found!')
                if log.closed:
                    log.open('log.naspy', 'a')
                log.write('%s\n' % msg)

    def discover_switch_spoofing(self, pkt):
        if pkt is not None:
            src = pkt.eth.src
            if pkt.dtp.tat == '0x00000000':
                for switch in self.switches_table:
                    if switch.contains(src) and not switch.get_port(src).negotiation:
                        port_name = switch.get_port(src).name
                        switch.get_port(src).negotiation = True
                        switch.get_port(src).negotiation_rcvd = True
                        msg = "Alert, interface %s on switch %s allow trunk negotiation!" % (port_name, switch.name)
                        sender = LogSender()
                        sender.send(msg, 'Switch Spoofing Found!')
                        print(msg)
                        self.log.write(msg)
            else:
                for switch in self.switches_table:
                    if switch.contains(src) and switch.get_port(src).negotiation:
                        port_name = switch.get_port(src).name
                        switch.get_port(src).negotiation = False
                        switch.get_port(src).no_nego_count = 0
                        msg = "Interface %s on switch %s no longer allow trunk negotiation!" % (port_name, switch.name)
                        print(msg)
                        self.log.write(msg)

    def discover_topology_changes(self, my_host_interface, password):
        net_interface = NetInterface(my_host_interface, password)
        net_interface.timeout = 35
        net_interface.wait_for_initial_information()
        net_interface.ssh_no_credential_connection()
        switch_port_mac = net_interface.switch_MAC
        for switch in self.switches_table:
            bridge_id_min = dict()
            root_port = dict()
            blocked_port = dict()
            if switch.contains(switch_port_mac):
                self.switch_baseline = copy.deepcopy(switch.spanning_tree_instances)
                if switch.connected_interface is not None:
                    net_interface.ssh.enable_monitor_mode_on_interface_range(switch.get_interfaces())
                tc_capture = pyshark.LiveCapture(interface=net_interface.interface)
                try:
                    tc_capture.apply_on_packets(self.tc_pkt_callback, timeout=net_interface.timeout)
                except concurrent.futures.TimeoutError:
                    tc_capture.close()
                    print('Capture finished!')

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

    def tc_pkt_callback(self, pkt):
        self.discover_vlan_hopping(pkt, self.log)
        if pkt.highest_layer.upper() == 'STP':
            if pkt.eth.src == pkt.stp.bridge_hw and pkt.stp.port != '0x00008001':
                sender_mac = self.calculate_sender_mac(pkt.eth.src, pkt.stp.port)
            else:
                sender_mac = pkt.eth.src
            pkt_bridge_id = pkt.stp.bridge_hw
            switch = self.get_switch(pkt_bridge_id)
            if switch is not None:
                port = switch.get_port(sender_mac)
                pkt_vlan_id = pkt.stp.root_ext if pkt.stp.bridge_ext == '0' else pkt.stp.bridge_ext
                pkt_root_id = pkt.stp.root_hw
                if (pkt_vlan_id == 0 or pkt_root_id == 0) and 'type' in pkt.eth.field_names and pkt.eth.type == '0x00008100':
                    pkt_vlan_id = pkt.vlan.id

                if pkt_vlan_id in self.switch_baseline:
                    if pkt_bridge_id == self.switch_baseline[pkt_vlan_id].bridge_id:
                        if self.port_in_baseline(port, pkt_vlan_id):
                            #PRIORITY CHANGE
                            old_prio = self.switch_baseline[pkt_vlan_id].priority
                            tc_change = False
                            if int(pkt_vlan_id) + int(pkt.stp.root_prio) != old_prio:
                                msg = "Bridge (%s) priority on vlan %s is changed from %s to %s!!" % (pkt_bridge_id,
                                                                                                      pkt_vlan_id,
                                                                                                      old_prio,
                                                                                                      int(pkt_vlan_id) + int(pkt.stp.root_prio))
                                print(msg)
                                self.print_to_log(msg)
                                switch.set_stp_priority(pkt_vlan_id, pkt.stp.root_prio)
                                self.switch_baseline[pkt_vlan_id].priority = int(pkt.stp.root_prio) + int(pkt_vlan_id)
                                tc_change = True
                            #ROOT BRIDGE CHANGE
                            old_root_bridge = self.switch_baseline[pkt_vlan_id].root_bridge_id
                            if pkt_root_id != old_root_bridge:
                                msg = "Root Bridge Change! the new RB of vlan %s is %s" % (pkt_vlan_id, pkt_root_id)
                                print(msg)
                                self.print_to_log(msg)
                                switch.set_stp_root_id(pkt_vlan_id, pkt_root_id)
                                self.switch_baseline[pkt_vlan_id].root_bridge_id = pkt_root_id
                                tc_change = True
                            #PORT_STATUS_CHANGE
                            if pkt_vlan_id in port.pvlan_status:
                                port_status = port.pvlan_status[pkt_vlan_id]
                                if port_status != "Designated":
                                    msg = "Port %s on vlan %s has switched his state from %s to Designated" % (port.name, pkt_vlan_id, port_status)
                                    print(msg)
                                    self.print_to_log(msg)
                                    switch.set_designated_port(sender_mac, pkt_vlan_id, override=True)
                                    switch.increase_port_tc_counter(pkt_vlan_id, sender_mac)
                                for bport in self.switch_baseline[pkt_vlan_id].ports:
                                    if bport.MAC == port.MAC:
                                        self.switch_baseline[pkt_vlan_id].ports.remove(bport)

                            if tc_change:
                                switch.increase_tc_counter(pkt_vlan_id)
                        else:
                            if pkt_vlan_id not in port.pvlan_status:
                                msg = "New vlan (%s) has added at this trunk port %s" % (pkt_vlan_id, port.name)
                                print(msg)
                                self.print_to_log(msg)
                                switch.set_designated_port(sender_mac, pkt_vlan_id, priority=pkt.stp.root_prio, b_id=pkt_root_id, initialization=True)
                                self.add_port_to_baseline(port.MAC, pkt_vlan_id)
                else:
                    if pkt_vlan_id not in port.pvlan_status:
                        msg = "New vlan (%s) has added at this trunk port %s" % (pkt_vlan_id, port.name)
                        print(msg)
                        self.print_to_log(msg)
                        switch.set_designated_port(sender_mac, pkt_vlan_id, priority=pkt.stp.root_prio,
                                                   b_id=pkt_root_id, initialization=True)
                        self.add_port_to_baseline(port.MAC, pkt_vlan_id)
        else:
            sender_mac = pkt.eth.src
            #NEW TRUNK PORT DISCOVER
            if pkt.highest_layer.upper() == 'DTP':
                self.discover_switch_spoofing(pkt)
                if pkt.dtp.tas == '0x00000001' or pkt.dtp.tos == '0x00000001':
                    for switch in self.switches_table:
                        if switch.contains(sender_mac) and not switch.get_port(sender_mac).trunk:
                            msg = "port %s is now trunk!" % sender_mac
                            print(msg)
                            self.print_to_log(msg)
                            switch.get_port(sender_mac).trunk = True
                            for vlan in self.switch_baseline:
                                for port in self.switch_baseline[vlan].ports:
                                    if port.MAC == sender_mac:
                                        port.trunk = True

    def take_blocked_port_from_baseline(self):
        blocked_port = list()
        for vlan in self.switch_baseline:
            for port in self.switch_baseline[vlan].ports:
                if port not in blocked_port:
                    blocked_port.append(port)
        return blocked_port

    def find_root_port(self, my_host_interface):
        timeout = 20
        net_interface = NetInterface(my_host_interface)
        net_interface.timeout = timeout
        for switch in self.switches_table:
            if switch.connected_interface is not None:
                bridge_id_min = dict()
                root_port = dict()
                for vlan_id in switch.get_vlans():
                    bridge_id_min[vlan_id] = (60000, None) #Priority, Mac
                    root_port[vlan_id] = None

                for port in switch.get_blocked_port():
                    print("Waiting...")
                    time.sleep(timeout)
                    net_interface.parameterized_ssh_connection(port.MAC, switch.ip, switch.name, switch.password,
                                                               switch.en_password, switch.connected_interface, 20)
                    port_capture = pyshark.LiveCapture(interface=net_interface.interface,
                                                       display_filter="stp and stp.bridge.hw != %s" % switch.bridge_id)
                    net_interface.ssh.enable_monitor_mode_on_specific_port(port.name)
                    rcvd_pkt = dict()
                    print('start sniffing on %s (%s)...' % (port.name, port.MAC))
                    port_capture.sniff(packet_count=len(switch.get_vlans()), timeout=timeout)
                    if port_capture:
                        for pkt in port_capture:
                            if 'type' in pkt.eth.field_names and pkt.eth.type == '0x00008100':
                                port.trunk = True
                                tagged_vlan = pkt.vlan.id
                                switch.set_blocked_port(port.MAC, tagged_vlan, initialization=True)
                                vlan_id = pkt.stp.root_ext if pkt.stp.bridge_ext == '0' else pkt.stp.bridge_ext
                                if vlan_id not in rcvd_pkt:
                                    rcvd_pkt[vlan_id] = pkt
                                if tagged_vlan != vlan_id:
                                    switch.set_blocked_port(port.MAC, vlan_id, priority=pkt.stp.root_prio,
                                                            b_id=pkt.stp.root_hw, initialization=True)
                            else:
                                vlan_id = pkt.stp.root_ext if pkt.stp.bridge_ext == '0' else pkt.stp.bridge_ext

                                if vlan_id not in rcvd_pkt:
                                    rcvd_pkt[vlan_id] = pkt

                                switch.set_blocked_port(port.MAC, vlan_id, priority=pkt.stp.root_prio,
                                                        b_id=pkt.stp.root_hw, initialization=True)
                        if not port.trunk:
                            pkt = port_capture[0]
                            if pkt.stp.bridge_ext == '0' and pkt.stp.root_ext == '0':
                                if 'pvst' in pkt.stp.field_names:
                                    vlan = pkt.stp.pvst.origvlan
                            else:
                                vlan = pkt.stp.root_ext if pkt.stp.bridge_ext == '0' else pkt.stp.bridge_ext

                            bridge_id_min[vlan], root_port[vlan] = self.get_min_bridge_id(pkt, bridge_id_min[vlan],
                                                                                          port.MAC, root_port[vlan])
                        else:
                            for vlan in port.get_vlan():
                                if port.pvlan_status[vlan] == "Blocked":
                                    if vlan not in bridge_id_min:
                                        bridge_id_min[vlan] = (60000, None)
                                    if vlan not in root_port:
                                        root_port[vlan] = None
                                    if vlan in rcvd_pkt:
                                        bridge_id_min[vlan], root_port[vlan] = self.get_min_bridge_id(rcvd_pkt[vlan],
                                                                                                      bridge_id_min[vlan],
                                                                                                      port.MAC,
                                                                                                      root_port[vlan])
                    port_capture.close()
                for vlan_id in switch.get_vlans():
                    if root_port[vlan_id] is not None:
                        switch.set_root_port(root_port[vlan_id], vlan_id, override=True)

    @staticmethod
    def get_min_bridge_id(pkt, bridge_min_id, port_mac, root_port, blocked_port=0):
        if int(pkt.stp.bridge_prio) < bridge_min_id[0]:
            priority_min = int(pkt.stp.bridge_prio)
            mac_min = pkt.stp.bridge_hw
            bridge_min_id = (priority_min, mac_min)
            if blocked_port != 0 and root_port is not None:
                blocked_port = root_port
            root_port = port_mac
        else:
            if bridge_min_id[1] is None:
                priority_min = int(pkt.stp.bridge_prio)
                mac_min = pkt.stp.bridge_hw
                bridge_min_id = (priority_min, mac_min)
                if blocked_port != 0 and root_port is not None:
                    blocked_port = root_port
                root_port = port_mac
            else:
                if int(pkt.stp.bridge_prio) == bridge_min_id[0]:
                    raw_mac_min = ''
                    raw_mac_curr = ''
                    mac_parts_min = bridge_min_id[1].split(':')
                    for part in mac_parts_min:
                        raw_mac_min += part
                    mac_parts_curr = pkt.stp.bridge_hw.split(':')
                    for part in mac_parts_curr:
                        raw_mac_curr += part

                    int_mac_min = int(raw_mac_min, 16)
                    int_mac_curr = int(raw_mac_curr, 16)

                    if int_mac_curr < int_mac_min:
                        priority_min = int(pkt.stp.bridge_prio)
                        mac_min = pkt.stp.bridge_hw
                        bridge_min_id = (priority_min, mac_min)
                        if blocked_port != 0  and root_port is not None:
                            blocked_port = root_port
                        root_port = port_mac
                    else:
                        if blocked_port != 0:
                            blocked_port = port_mac
                else:
                    if blocked_port != 0:
                        blocked_port = port_mac

        return (bridge_min_id, root_port) if (blocked_port == 0) else (bridge_min_id, root_port, blocked_port)

    def set_connected_interface_status(self, my_host_interface):
        print("Check connected interface status")
        stp_capture = pyshark.LiveCapture(interface=my_host_interface, display_filter="stp")
        stp_capture.sniff(packet_count=1, timeout=10)
        if stp_capture:
            pkt = stp_capture[0]
            stp_capture.close()
            vlan = pkt.stp.root_ext if pkt.stp.bridge_ext == '0' else pkt.stp.bridge_ext

            if pkt.eth.src == pkt.stp.bridge_hw and pkt.stp.port != '0x00008001':
                port_mac = self.calculate_sender_mac(pkt.eth.src, pkt.stp.port)
            else:
                port_mac = pkt.eth.src

            for switch in self.switches_table:
                if switch.contains(port_mac):
                    switch.set_designated_port(port_mac, vlan, initialization=True)
        else:
            print("STP Capture Timeout!")

        dtp_capture = pyshark.LiveCapture(interface=my_host_interface, display_filter="dtp")
        dtp_capture.sniff(packet_count=1, timeout=30)
        if dtp_capture:
            self.discover_switch_spoofing(dtp_capture[0])
        else:
            print("DTP Capture Timeout!")

    def add_switch(self, switch):
        if switch not in self.switches_table:
            self.switches_table.append(switch)

    def print_switches_status(self):
        for switch in self.switches_table:
            print("\nSwitch %s:" % switch.name)
            self.print_to_log(switch.print_spanning_tree())
            self.print_to_log(switch.print_trunk_ports())

    def get_switch(self, switch_id):
        for switch in self.switches_table:
            if switch.bridge_id == switch_id:
                return switch
        return None

    def add_port_to_baseline(self, port_mac, vlan_id):
        for vlan in self.switch_baseline:
            for port in self.switch_baseline[vlan].ports:
                if port.MAC == port_mac:
                    base_port = port
                    break
        if base_port is not None:
            base_port.set_port_as_designated(vlan_id, initialization=True)
            if vlan_id in self.switch_baseline:
                self.switch_baseline[vlan_id].add_port(base_port)
            else:
                self.switch_baseline[vlan_id] = SpanningTreeInstance(vlan_id)
                self.switch_baseline[vlan_id].add_port(base_port)

    def port_in_baseline(self, port, vlan_id):
        if len(self.switch_baseline[vlan_id].ports) > 0 and port is not None:
            for p in self.switch_baseline[vlan_id].ports:
                if port.MAC == p.MAC:
                    return True
        return False

    def print_to_log(self, msg):
        if self.log.closed:
            self.log = open('log.naspy', 'a')
        self.log.write('%s - \n%s \n' % (datetime.now().strftime("%H:%M:%S"), msg))
