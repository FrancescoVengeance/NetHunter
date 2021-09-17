from monitors.dhcp_monitor import DHCPMonitor
from safe_print import SafePrint
from packets_queue import PacketsQueue
import sys


if __name__ == '__main__':
    interface = sys.argv[1]
    packets = PacketsQueue()
    safe_print = SafePrint()
    dhcp = DHCPMonitor(interface, packets, safe_print)
    dhcp.start()
    dhcp.join()
