
class DHCPServer:
    def __init__(self, ip: str, mac:str, subnet: str):
        self.ip: str = ip
        self.mac: str = mac
        self.subnet: str = subnet
        self.no_response_count: int = 0

    def get_info(self) -> str:
        return f"IP: {self.ip} | MAC: {self.mac} | Subnet: {self.subnet}"

    def restore_response_count(self) -> None:
        self.no_response_count = 0

    def increase_response_count(self) -> None:
        self.no_response_count += 1

    def __eq__(self, other):
        return self.mac == other.mac
