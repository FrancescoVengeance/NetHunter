class Port:
    def __init__(self, name: str, mac: str):
        self.name = name
        self.mac = mac
        self.pvlan_status = {}
        self.pvlan_status_change_counter = {}
        self.trunk = False
        self.negotiation = False
        self.negotiation_rcvd = False
        self.no_negotiation_count = 0

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

    # finire di scrivere questa classe
