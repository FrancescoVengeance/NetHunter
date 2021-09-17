from monitors.dhcp_monitor import DHCPMonitor
from safe_print import SafePrint
from packets_queue import PacketsQueue
import sys
from sniffer import Sniffer

if __name__ == '__main__':
    interface = sys.argv[1]
    packets = PacketsQueue()
    safe_print = SafePrint()
    sniffer = Sniffer(interface, packets)
    dhcp = DHCPMonitor(interface, packets, safe_print)
    sniffer.start()
    dhcp.start()
    dhcp.join()
    sniffer.join()
