from port import Port
from spanning_tree import SpanningTree


class Switch:
    def __init__(self, name: str, ip: str, password: str, enable: str, connected_interface):
        self.name = name
        self.ip: str = ip
        self.password: str = password
        self.enable_password: str = enable
        self.connected_interface = connected_interface
        self.bridge_id = None
        self.ports: [Port] = []
        self.spanning_tree_instances: {int, SpanningTree} = {}

    def get_interfaces(self) -> list:
        interfaces = []
        for port in self.ports:
            interfaces.append(port.name)
        return interfaces

    def set_spanning_tree_priority(self, vlan_id: int, priority: int) -> None:
        self.spanning_tree_instances[vlan_id].priority = int(priority) + int(vlan_id)
        self.spanning_tree_instances[vlan_id].check_root_bridge()

    def set_spanning_tree_root_id(self, vlan: int, root_id: int) -> None:
        self.spanning_tree_instances[vlan].root_bridge_id = root_id
        self.spanning_tree_instances[vlan].check_root_bridge()

    def add_ports(self, port: Port):
        if port not in self.ports:
            self.ports.append(port)

    def set_designated_port(self, port_address: str, vlan_id: int, override=False, priority=None, b_id=None, initialization=False):
        for port in self.ports:
            if port.mac == port_address:
                self.add_port_to_spanning_tree(vlan_id, port, priority, b_id)
                port.set_port_as_designated(vlan_id, override, initialization)

    def set_blocked_port(self, port_address: str, vlan_id: int, override=False, priority=None, b_id=None, initialization=False) -> None:
        for port in self.ports:
            if port.mac == port_address:
                self.add_port_to_spanning_tree(vlan_id, port, priority, b_id)
                port.set_port_as_blocked(vlan_id, override, initialization)

    def set_root_port(self, port_address: str, vlan_id: int, override=False, priority=None, b_id=None, initialization=False) -> None:
        for port in self.ports:
            if port.mac == port_address:
                self.add_port_to_spanning_tree(vlan_id, port, priority, b_id)
                port.set_port_as_root(vlan_id, override, initialization)

    def get_spanning_tree(self) -> str:
        message = ""
        for vlan_id in self.spanning_tree_instances:
            self.spanning_tree_instances[vlan_id].ports.sort(key=self.get_mac)
            message += f"{self.spanning_tree_instances[vlan_id].get_status()}\n"
        return message

    @staticmethod
    def get_mac(port):
        return port.mac

    def get_trunk_ports_info(self) -> str:
        message = "Trunk ports:\n"
        trunk = False
        for port in self.ports:
            if port.trunk:
                trunk = True
                message += f"Port: {port.name} | Vlans: {str(port.get_vlans())}\n"

        if not trunk:
            message += "No trunk ports in this switch!"

        return message

    def get_port(self, mac: str) -> Port:
        for port in self.ports:
            if port.mac == mac:
                return port

    def get_port_by_name(self, name: str) -> Port:
        for port in self.ports:
            if port.name == name:
                return port

    def contains(self, port_address) -> bool:
        if port_address == self.bridge_id:
            return True
        for port in self.ports:
            if port.mac == port_address:
                return True

        return False

    def increase_tc_counter(self, vlan_id) -> None:
        self.spanning_tree_instances[vlan_id].increase_tc_counter()

    def increase_port_tc_counter(self, vlan_id, mac) -> None:
        self.get_port(mac).increase_status_change_counter(vlan_id)

    def add_port_to_spanning_tree(self, vlan_id, port: Port, priority=None, root_bridge_id=None) -> None:
        if vlan_id in self.spanning_tree_instances:
            self.spanning_tree_instances[vlan_id].add_port(port)
        else:
            self.spanning_tree_instances[vlan_id] = SpanningTree(vlan_id)
            self.spanning_tree_instances[vlan_id].add_port(port)
        if root_bridge_id is not None and priority is not None:
            self.spanning_tree_instances[vlan_id].update_spanning_tree_info(priority, self.bridge_id, root_bridge_id)

    def remove_port_from_stp(self, vlan_id, port: Port) -> None:
        self.spanning_tree_instances[vlan_id].remove_port(port)
        if len(self.spanning_tree_instances[vlan_id].ports) == 0:
            del self.spanning_tree_instances[vlan_id]

    def there_is_root_port(self, vlan_id) -> bool:
        return self.spanning_tree_instances[vlan_id].there_is_root_port()

    def get_vlans(self) -> list:
        return list(self.spanning_tree_instances.keys())

    def all_root_ports_found(self) -> bool:
        for vlan_id in self.get_vlans():
            if not self.spanning_tree_instances[vlan_id].root_bridge:
                found = self.spanning_tree_instances[vlan_id].there_is_root_port()
                if not found:
                    return False
        return True

    def get_trunk_ports(self) -> list:
        ports = []
        for port in self.ports:
            if port.trunk:
                ports.append(port)
        return ports

    def get_blocked_ports(self) -> list:
        ports = []
        for port in self.ports:
            if len(port.pvlan_status) == 0 or port.trunk:
                ports.append(port)
        return ports

    def get_blocked_ports_per_vlan(self, vlan_id) -> list:
        ports = []
        for port in self.ports:
            if port.pvlan_status[vlan_id] == "Blocked":
                ports.append(port)
        return ports
