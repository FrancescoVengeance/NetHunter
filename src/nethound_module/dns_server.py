class DNServer:
    def __init__(self, ip: str, mac: str):
        self.ip = ip
        self.mac = mac
        self.no_response_count = 0

    def get_info(self) -> str:
        return f"IP: {self.ip} | MAC: {self.mac}"

    def restore_no_response_count(self) -> None:
        self.no_response_count = 0

    def increase_no_response_count(self) -> None:
        self.no_response_count += 1

    def __eq__(self, other):
        return self.mac == other.mac
