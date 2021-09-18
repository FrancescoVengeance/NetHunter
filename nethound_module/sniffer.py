from threading import Thread
from packets_queue import PacketsQueue
import pyshark
from time import sleep


class Sniffer(Thread):
    def __init__(self, interface: str, packets: PacketsQueue):
        super(Sniffer, self).__init__()
        self.packets = packets
        self.interface = interface

    def run(self) -> None:
        while True:
            capture = pyshark.LiveCapture(interface=self.interface,)
            for packet in capture.sniff_continuously(packet_count=2):
                self.packets.put(packet)
            sleep(4)
