import concurrent.futures
import threading
from NetInterface import *
from Monitors import *
from datetime import datetime
import sys
import pyshark


def print_help():
    return "Usage: -i [interface], [-m [mode]], [-p [password]], [-h [help]]\n" \
           "mode options: \n" \
           "arp: IDS system for ARP protocol.\n" \
           "dhcp: IDS system for Rogue DHCP Attack\n" \
           "dns: IDS system for DNS Hijack Attack\n" \
           "stp: Monitoring STP Status and eventually failure\n" \
           "default: When no other options are chosen this script will perform all modality\n" \
           "password: is the password use for decrypting switch credentials"


def parse_args():
    if os.geteuid() != 0:
        print("You need to run as a root")
        print(print_help())
        sys.exit(0)

    if len(sys.argv) < 3:
        print("[ERROR] you must enter an interface and a modality")
        print(print_help())
        sys.exit(0)

    modalities = ["arp", "dhcp", "vlan", "stp", "dns"]

    interface = None
    if "-i" in sys.argv:
        interface = sys.argv[sys.argv.index("-i") + 1]
        print(f"interface {interface}")
    elif "-h" in sys.argv:
        print(print_help())
        sys.exit(0)

    mode = "all"
    if len(sys.argv) > 4 and "-m" in sys.argv:
        mode = sys.argv[sys.argv.index("-m") + 1] if sys.argv[sys.argv.index("-m") + 1] in modalities else "all"
    print(f"mode setted to {mode}")

    password = None
    if len(sys.argv) > 4 and "-p" in sys.argv:
        password = sys.argv[sys.argv.index("-p") + 1]
        print(f"password {password}")

    timeout = int(sys.argv[sys.argv.index("-t") + 1]) if "-t" in sys.argv else 60

    return interface, mode, password, timeout


def update_callback(pkt):
    if mode == 'all':
        if pkt.highest_layer.upper() == 'ARP':
            sender_port = None
            target_port = None
            for switch in stp_monitor.switches_table:
                if switch.contains(pkt.arp.src_hw_mac):
                    sender_port = switch.get_port(pkt.arp.src_hw_mac)

                if switch.contains(pkt.arp.dst_hw_mac):
                    target_port = switch.get_port(pkt.arp.dst_hw_mac)

            arp_monitor.update_arp_table(pkt, sender_port, target_port)
        if pkt.highest_layer.upper() == 'BOOTP':
            dhcp_monitor.update_dhcp_servers(pkt)
        if pkt.highest_layer.upper() == 'DNS':
            dns_monitor.update_dns_servers(pkt)
        stp_monitor.update_switches_table(pkt)
        stp_monitor.discover_vlan_hopping(pkt, log)

    if mode == 'dns' and pkt.highest_layer.upper() == 'DNS':
        dns_monitor.update_dns_servers(pkt)

    if mode == 'stp':
        stp_monitor.update_switches_table(pkt)
        stp_monitor.discover_vlan_hopping(pkt, log)

    if mode == 'dhcp' and pkt.highest_layer.upper() == 'BOOTP':
        dhcp_monitor.update_dhcp_servers(pkt)

    if mode == 'arp' and pkt.highest_layer.upper() == 'ARP':
        arp_monitor.update_arp_table(pkt)


if __name__ == "__main__":
    interface, mode, password, timeout = parse_args()
    net_interface = NetInterface(interface, password)
    net_interface.timeout = timeout

    log = "log"

    stp_monitor = STPMonitor(log)
    arp_monitor = ArpMonitor(log)
    dhcp_monitor = RogueDHCPMonitor(log)
    dns_monitor = RogueDNSMonitor(log)

    topology_cng_packet = None
    capture = pyshark.LiveCapture(interface=net_interface.interface)

    try:
        if mode in ["stp", "all"]:
            net_interface.wait_for_initial_information()
            if net_interface.ssh_no_credential_connection():
                stp_monitor.add_switch(net_interface.take_interfaces())
                net_interface.enable_monitor_mode()

            print("start sniffing")
            try:
                await capture.apply_on_packets(update_callback, timeout=net_interface.timeout)
            except concurrent.futures.TimeoutError:
                capture.close()
                print("capture finished")

            stp_monitor.set_connected_interface_status(interface)
            stp_monitor.find_root_port(interface)
            stp_monitor.print_switches_status()

            while True:
                time.sleep(3)
                if mode in ["dhcp", "all"]:
                    dhcp_discover = threading.Thread(target=net_interface.send_dhcp_discover)
                    dhcp_discover.start()
                    dhcp_discover.join()
                if mode in ["dns", "all"]:
                    dns_query = threading.Thread(target=net_interface.send_dns_query)
                    dns_query.start()
                    dns_query.join()

                print("Start sniffing")
                capture = pyshark.LiveCapture(interface=net_interface.interface)
                try:
                    capture.apply_on_packets(update_callback, timeout=net_interface.timeout)
                except concurrent.futures.TimeoutError:
                    capture.close()
                    print("Caputure finished")

                dhcp_monitor.print_dhcp_servers()
                dhcp_monitor.increase_counter()
                dns_monitor.print_dns_servers()
                dns_monitor.increase_counter()
                arp_monitor.print_ip_arp_table()

                if mode in ["stp", "all"]:
                    time.sleep(stp_monitor.waiting_timer / 2)
                    print("Finding topology changes...")
                    topology_cng_packet = pyshark.LiveCapture(interface=interface, display_filter="stp.flags.tc == 1")
                    topology_cng_packet.sniff(packet_count=1, timeout=180)

                    if topology_cng_packet:
                        print("Found changes in topology")
                        stp_monitor.discover_topology_changes(interface, password)
                        stp_monitor.print_switches_status()
                        time.sleep(stp_monitor.waiting_timer)
                    else:
                        print("No changes found")
                        stp_monitor.print_switches_status()
                current_time = datetime.now().strftime("%H:%M:%S")

                # if è mezzanotte:
                #   manda i log per mail
    # except (KeyboardInterrupt, RuntimeError, TypeError):
    #     if topology_cng_packet is not None:
    #         topology_cng_packet.close()
    #     capture.eventloop.close()
    #     print("BYE!")
    finally:
        pass