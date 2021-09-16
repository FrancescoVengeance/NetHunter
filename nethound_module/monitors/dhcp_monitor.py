from nethound_module.network_elements.dhcp_server import DHCPServer
from threading import Thread
from time import sleep
from nethound_module.packets_queue import PacketsQueue


class DHCPMonitor(Thread):
    def __init__(self, packets: PacketsQueue):
        super().__init__()
        self.dhcp_servers: list = []
        self.packets: PacketsQueue = packets

    def run(self) -> None:
        pass
