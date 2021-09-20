from threading import Thread
from packets_buffer import PacketsBuffer
import pyshark
from time import sleep


class Sniffer(Thread):
    def __init__(self, interface: str, packets: PacketsBuffer):
        super(Sniffer, self).__init__()
        self.packets = packets
        self.interface = interface
        self.display_filter = "udp.srcport == 67 or udp.srcport == 53"
        self.capture = pyshark.LiveCapture(interface=self.interface, display_filter=self.display_filter)

    def run(self) -> None:
        while True:
            count: int = 1
            for packet in self.capture.sniff_continuously():
                if (count % 5) != 0:
                    print("sniffing...")
                    self.packets.put(packet)
                else:
                    sleep(8)
                count += 1
