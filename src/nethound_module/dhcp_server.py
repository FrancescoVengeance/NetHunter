
class DHCPServer:
    def __init__(self, ip: str, mac: str, subnet: str, default_gateway: str = "", dns_server: str = ""):
        self.ip: str = ip
        self.mac: str = mac
        self.subnet: str = subnet
        self.default_gateway: str = default_gateway
        self.dns_server: str = dns_server
        self.no_response_count: int = 0

    def get_info(self) -> str:
        return f"IP: {self.ip} | MAC: {self.mac} | Subnet: {self.subnet} | Default gateway: {self.default_gateway} " \
               f"| DNS: {self.dns_server}"

    def restore_no_response_count(self) -> None:
        self.no_response_count = 0

    def increase_no_response_count(self) -> None:
        self.no_response_count += 1

    def __eq__(self, other):
        return self.mac == other.mac
