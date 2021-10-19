from builtins import print


class DHCPServer:

    def __init__(self, ip_address, mac_address, subnet):
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.subnet = subnet
        self.no_response_count = 0

    def print_info(self):
        msg = 'Ip Address: %s MAC address: %s Subnet %s' % (self.ip_address, self.mac_address, self.subnet)
        print(msg)
        return msg

    def set_ip_address(self, ip_address):
        self.ip_address = ip_address

    def restore_response_count(self):
        self.no_response_count = 0

    def increase_response_count(self):
        self.no_response_count += 1

    def equals(self, n_mac_address):
        return True if self.mac_address == n_mac_address else False


class DNSServer:

    def __init__(self, ip_address, mac_address):
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.no_response_count = 0

    def print_info(self):
        msg = 'Ip Address: %s MAC address: %s' % (self.ip_address, self.mac_address)
        print(msg)
        return msg

    def set_ip_address(self, ip_address):
        self.ip_address = ip_address

    def restore_response_count(self):
        self.no_response_count = 0

    def increase_response_count(self):
        self.no_response_count += 1

    def equals(self, n_mac_address):
        return True if self.mac_address == n_mac_address else False


class ARPTable:

    def __init__(self):
        self.ip_arp_table = dict()
        self.mac_arp_table = dict()

    def add_couple(self, ip, mac):
        if ip in self.ip_arp_table:
            if not (mac in self.ip_arp_table[ip]):
                self.ip_arp_table[ip].append(mac)
                if len(self.ip_arp_table[ip]) > 1:
                    print("Conflict Found, duplicate IP address: %s with this mac: %s" % (ip, self.ip_arp_table[ip]))
        else:
            self.ip_arp_table[ip] = list()
            self.ip_arp_table[ip].append(mac)
            if len(self.ip_arp_table[ip]) > 1:
                print("Conflict Found, duplicate IP address: %s with this mac: %s" % (ip, self.ip_arp_table[ip]))

        if mac in self.mac_arp_table:
            if not (ip in self.mac_arp_table[mac]):
                self.mac_arp_table[mac].append(ip)
                if len(self.mac_arp_table[mac]) > 1:
                    print("Conflict Found, duplicate mac address: %s with this IPs: %s" % (mac, self.mac_arp_table[mac]))
        else:
            self.mac_arp_table[mac] = list()
            self.mac_arp_table[mac].append(ip)
            if len(self.mac_arp_table[mac]) > 1:
                print("Conflict Found, duplicate mac address: %s with this IPs: %s" % (mac, self.mac_arp_table[mac]))

    def print_ip_arp_table(self):
        for ip in self.ip_arp_table:
            print("IP %s - MAC: %s" % (ip, str(self.ip_arp_table[ip])[1:-1]))

    def print_mac_arp_table(self):
        for mac in self.mac_arp_table:
            print("MAC %s - IP: %s" % (mac, str(self.mac_arp_table[mac])[1:-1]))


class SpanningTreeInstance:

    def __init__(self, vlan_id):
        self.ports = list()
        self.vlan_id = vlan_id
        self.priority = 60000
        self.bridge_id = None
        self.root_bridge_id = None
        self.root_bridge = False
        self.tc_counter = 0

    def get_blocked_port(self):
        out = list()
        for port in self.ports:
            if port.pvlan_status[self.vlan_id] == "Blocked":
                out.append(port)
        return out

    def add_port(self, port):
        if port not in self.ports:
            self.ports.append(port)

    def remove_port(self, port):
        if port in self.ports:
            self.ports.remove(port)

    def increase_tc_counter(self):
        self.tc_counter += 1

    def update_stp_info(self, priority, bridge_id, root_bridge_id):
        self.priority = int(priority) + int(self.vlan_id)
        self.bridge_id = bridge_id
        self.root_bridge_id = root_bridge_id
        self.check_root_bridge()

    def check_root_bridge(self):
        self.root_bridge = True if self.bridge_id == self.root_bridge_id else False

    def there_is_root_port(self):
        for port in self.ports:
            if port.pvlan_status[self.vlan_id] == "Root":
                return True
        return False

    def print_stp_status(self):
        msg = "Spanning Tree on Vlan: %s\n" % self.vlan_id
        print("Spanning Tree on Vlan: %s" % self.vlan_id)
        print("  Root Bridge: %s - Bridge: %s - Priority: %s" % (self.root_bridge_id, self.bridge_id, self.priority))
        msg += "   Root Bridge: %s - Bridge: %s - Priority: %s \n" % (self.root_bridge_id, self.bridge_id, self.priority)
        if self.root_bridge:
            print("  This switch is the Root Bridge")
            msg += "  This switch is the Root Bridge\n"
        print("  Recents Topology Change: %s" % self.tc_counter)
        msg += "  Recents Topology Change: %s\n" % self.tc_counter
        for port in self.ports:
            if port.negotiation:
                print("\tPort: %s(!) - Address: %s, Status: %s - #Rec_CNG: %s" % (port.name, port.MAC,
                                                                               port.pvlan_status[self.vlan_id],
                                                                               port.pvlan_status_change_counter[
                                                                                   self.vlan_id]))
                msg += "\tPort: %s(!) - Address: %s, Status: %s - #Rec_CNG: %s\n" % (port.name, port.MAC,
                                                                                  port.pvlan_status[self.vlan_id],
                                                                                  port.pvlan_status_change_counter[
                                                                                      self.vlan_id])
            else:
                print("\tPort: %s - Address: %s, Status: %s - #Rec_CNG: %s" % (port.name, port.MAC,
                                                                               port.pvlan_status[self.vlan_id],
                                                                               port.pvlan_status_change_counter[self.vlan_id]))
                msg += "\tPort: %s - Address: %s, Status: %s - #Rec_CNG: %s\n" % (port.name, port.MAC,
                                                                                  port.pvlan_status[self.vlan_id],
                                                                                  port.pvlan_status_change_counter[self.vlan_id])
        print("(!) - Port allow trunk negotiations!")
        msg += "(!) - Port allow trunk negotiations!\n"
        return msg


class Switch:

    def __init__(self, n, ip, pwd, en_pwd, conn_interface):
        self.name = n
        self.bridge_id = None
        self.ports = list()
        self.ip = ip
        self.password = pwd
        self.en_password = en_pwd
        self.connected_interface = conn_interface
        self.spanning_tree_instances = dict()

    def get_interfaces(self):
        interfaces = list()
        for port in self.ports:
            interfaces.append(port.name)
        return interfaces

    def set_stp_priority(self, vlan, priority):
        self.spanning_tree_instances[vlan].priority = int(priority) + int(vlan)

    def set_stp_root_id(self, vlan, root_id):
        self.spanning_tree_instances[vlan].root_bridge_id = root_id
        self.spanning_tree_instances[vlan].check_root_bridge()

    def add_ports(self, port):
        if port not in self.ports:
            self.ports.append(port)

    def set_designated_port(self, port_address, vlan_id, override=False, priority=None, b_id=None, initialization=False):
        for port in self.ports:
            if port.MAC == port_address:
                self.add_port_to_spanning_tree(vlan_id, port, priority, b_id)
                port.set_port_as_designated(vlan_id, override, initialization)

    def set_blocked_port(self, port_address, vlan_id, override=False, priority=None, b_id=None, initialization=False):
        for port in self.ports:
            if port.MAC == port_address:
                self.add_port_to_spanning_tree(vlan_id, port, priority, b_id)
                port.set_port_as_blocked(vlan_id, override, initialization)

    def set_root_port(self, port_address, vlan_id, override=False, priority=None, b_id=None, initialization=False):
        for port in self.ports:
            if port.MAC == port_address:
                self.add_port_to_spanning_tree(vlan_id, port, priority, b_id)
                port.set_port_as_root(vlan_id, override, initialization)

    def print_spanning_tree(self):
        msg = ''
        for vlan_id in self.spanning_tree_instances:
            self.spanning_tree_instances[vlan_id].ports.sort(key=self.take_MAC)
            msg += '%s \n' % self.spanning_tree_instances[vlan_id].print_stp_status()
        return msg

    def print_trunk_ports(self):
        out_msg = 'Trunk Ports:\n'
        print("Trunk Ports:")
        there_is_trunks = False
        for port in self.ports:
            if port.trunk:
                there_is_trunks = True
                msg = "Port %s - vlans: %s" % (port.name, port.print_vlans())
                out_msg += '%s \n' % msg
                print(msg)

        if not there_is_trunks:
            print("In this switch there are not Trunk Ports!\n")
            out_msg += 'In this switch there are not Trunk Ports!\n'
        else:
            print('')
        return out_msg

    @staticmethod
    def take_MAC(port):
        return port.MAC

    def get_port(self, port_mac):
        for port in self.ports:
            if port.MAC == port_mac:
                return port

    def get_port_by_name(self, port_name):
        for port in self.ports:
            if port.name == port_name:
                return port

    def contains(self, port_address):
        for port in self.ports:
            if port.MAC == port_address:
                return True
        if port_address == self.bridge_id:
            return True
        return False

    def increase_tc_counter(self, vlan):
        self.spanning_tree_instances[vlan].increase_tc_counter()

    def increase_port_tc_counter(self, vlan, port_mac):
        self.get_port(port_mac).increase_status_change_counter(vlan)

    def add_port_to_spanning_tree(self, vlan_id, port, priority=None, r_id=None):
        if vlan_id in self.spanning_tree_instances:
            self.spanning_tree_instances[vlan_id].add_port(port)
        else:
            self.spanning_tree_instances[vlan_id] = SpanningTreeInstance(vlan_id)
            self.spanning_tree_instances[vlan_id].add_port(port)
        if r_id is not None and priority is not None:
            self.spanning_tree_instances[vlan_id].update_stp_info(priority, self.bridge_id, r_id)

    def remove_port_from_stp(self, vlan_id, port):
        self.spanning_tree_instances[vlan_id].remove_port(port)
        if len(self.spanning_tree_instances[vlan_id].ports) == 0:
            del self.spanning_tree_instances[vlan_id]

    def there_is_root_port(self, vlan_id):
        return self.spanning_tree_instances[vlan_id].there_is_root_port()

    def all_root_port_found(self):
        for vlan_id in self.get_vlans():
            if not self.spanning_tree_instances[vlan_id].root_bridge:
                found = self.spanning_tree_instances[vlan_id].there_is_root_port()

                if not found:
                    return False
        return True

    def get_trunk_port(self):
        out = list()
        for port in self.ports:
            if port.trunk:
                out.append(port)
        return out

    def get_blocked_port(self):
        out = list()
        for port in self.ports:
            if len(port.pvlan_status) == 0 or port.trunk:
                out.append(port)
        return out

    def get_blocked_port_per_vlan(self, vlan_id):
        out = list()
        for port in self.ports:
            if port.pvlan_status[vlan_id] == 'Blocked':
                out.append(port)
        return out

    def get_vlans(self):
        return self.spanning_tree_instances.keys()


class Port:
    def __init__(self, n, m):
        self.name = n
        self.MAC = m
        self.pvlan_status = dict()
        self.pvlan_status_change_counter = dict()
        self.trunk = False
        self.negotiation = False
        self.negotiation_rcvd = False
        self.no_nego_count = 0

    def set_port_as_designated(self, vlan_id=1, override=False, initialization=False):
        if len(self.pvlan_status) > 0 and vlan_id not in self.pvlan_status and not self.trunk:
            self.trunk = True
        if override or vlan_id not in self.pvlan_status:
            self.pvlan_status[vlan_id] = "Designated"
            if initialization:
                self.pvlan_status_change_counter[vlan_id] = 0

    def set_port_as_root(self, vlan_id=1, override=False, initialization=False):
        if len(self.pvlan_status) > 0 and vlan_id not in self.pvlan_status and not self.trunk:
            self.trunk = True
        if override or vlan_id not in self.pvlan_status:
            self.pvlan_status[vlan_id] = "Root"
            if initialization:
                self.pvlan_status_change_counter[vlan_id] = 0

    def set_port_as_blocked(self, vlan_id=1, override=False, initialization=False):
        if len(self.pvlan_status) > 0 and vlan_id not in self.pvlan_status and not self.trunk:
            self.trunk = True
        if override or vlan_id not in self.pvlan_status:
            self.pvlan_status[vlan_id] = "Blocked"
            if initialization:
                self.pvlan_status_change_counter[vlan_id] = 0

    def increase_status_change_counter(self, vlan):
        if vlan in self.pvlan_status_change_counter:
            self.pvlan_status_change_counter[vlan] += 1
        else:
            self.pvlan_status_change_counter[vlan] = 0

    def get_vlan(self):
        return list(self.pvlan_status.keys())

    def print_vlans(self):
        out = list()
        for key in self.get_vlan():
            out.append(key)
        return str(out)[1:-1]

    def contain_vlan(self, vlan_id):
        if vlan_id in self.pvlan_status:
            return True
        return False

    def remove_vlan(self, vlan_id, log=None):
        if vlan_id in self.pvlan_status:
            del self.pvlan_status[vlan_id]
            if len(self.pvlan_status) < 2 and self.trunk:
                self.trunk = False
                print("Port %s is no longer TRUNK!" % self.name)
                if log is not None:
                    log.write("Port %s is no longer TRUNK!" % self.name)
