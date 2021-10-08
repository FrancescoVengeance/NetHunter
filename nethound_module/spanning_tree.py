from port import Port


class SpanningTree:
    def __init__(self, vlan_id: int):
        self.ports: [Port] = []
        self.vlan_id: int = vlan_id
        self.priority = 60000
        self.bridge_id = None
        self.root_bridge_id = None
        self.root_bridge: bool = False
        self.topology_changes_counter: int = 0

    def get_blocked_ports(self) -> list:
        ports = []
        for port in self.ports:
            if port.pvlan_status[self.vlan_id] == "Blocked":
                ports.append(port)

        return ports

    def add_port(self, port: Port) -> None:
        if port not in self.ports:
            self.ports.append(port)

    def increase_tc_counter(self) -> None:
        self.topology_changes_counter += 1

    def update_spanning_tree_info(self, priority: int, bridge_id, root_bridge_id) -> None:
        self.priority = int(priority) + int(self.vlan_id)
        self.bridge_id = bridge_id
        self.root_bridge_id = root_bridge_id
        self.check_root_bridge()

    def check_root_bridge(self) -> None:
        self.root_bridge_id = True if self.bridge_id == self.root_bridge_id else False

    def there_is_root_port(self) -> bool:
        for port in self.ports:
            if port.pvlan_status[self.vlan_id] == "Root":
                return True
        return False

    def get_status(self) -> str:
        message = f"Spanning tree on Vlan: {self.vlan_id}\n"
        message += f"   Root bridge: {self.root_bridge_id} | Bridge: {self.bridge_id} | Priority: {self.priority}\n"
        if self.root_bridge:
            message += "   This switch is the Root bridge\n"
        message += f"   Recents topology change: {self.topology_changes_counter}\n"

        for port in self.ports:
            message += f"   Port: {port.name} | Address: {port.mac} | Status: {port.pvlan_status[self.vlan_id]} " \
                       f"| Recent changes: {port.pvlan_status_change_counter[self.vlan_id]}\n"
        message += "[WARNING] Port allows trunk negotiations"
        return message
