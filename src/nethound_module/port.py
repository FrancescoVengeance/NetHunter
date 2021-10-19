class Port:
    def __init__(self, name: str, mac: str):
        self.name: str = name
        self.mac: str = mac
        self.pvlan_status: dict = {}
        self.pvlan_status_change_counter: dict = {}
        self.trunk: bool = False
        self.negotiation: bool = False
        self.negotiation_rcvd: bool = False
        self.no_negotiation_count: int = 0

    def set_port_as_designated(self, vlan_id=1, override=False, initialization=False) -> None:
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

    def set_port_as_blocked(self, vlan_id=1, override=False, initialization=False) -> None:
        if len(self.pvlan_status) > 0 and vlan_id not in self.pvlan_status and not self.trunk:
            self.trunk = True
        if override or vlan_id not in self.pvlan_status:
            self.pvlan_status[vlan_id] = "Blocked"
            if initialization:
                self.pvlan_status_change_counter[vlan_id] = 0

    def increase_status_change_counter(self, vlan_id) -> None:
        if vlan_id in self.pvlan_status_change_counter:
            self.pvlan_status_change_counter[vlan_id] += 1
        else:
            self.pvlan_status_change_counter[vlan_id] = 0

    def get_vlans(self) -> list:
        return list(self.pvlan_status.keys())

    def contains_vlan(self, vlan_id) -> bool:
        return vlan_id in self.pvlan_status

    def remove_vlan(self, vlan_id, verbose=False) -> str:
        if vlan_id in self.pvlan_status:
            del self.pvlan_status[vlan_id]
            if len(self.pvlan_status) < 2 and self.trunk:
                self.trunk = False
                if verbose:
                    return f"Port {self.name} is no longer TRUNK!"