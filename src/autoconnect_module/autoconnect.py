from requests import *
from scapy.all import *
from scapy.layers.inet import TCP
from captiveportal.WifiDogCaptivePortal import WifiDogCaptivePortal
from captiveportal.NodogsplashCaptivePortal import NodogsplashCaptivePortal
from captiveportal.ZeroShellCaptivePortal import ZeroShellCaptivePortal
from connection.DHCPAttempt import DHCPAttempt
from connection.BroadcastAttempt import BroadcastAttempt
from connection.DataAttempt import DataAttempt
import argparse
from util.Options import Options
import logging
from util.LogSender import LogSender

def batch_connection(interface):
    # First checks if is possible to perform a DHCP transaction. Otherwise it sniffs for 20 seconds arp and tcp packets.
    # If the packet list is not empty and contains a TCP packet then uses DataAttempt otherwise use BroadcastAttempt.
    dhcp_attempt = DHCPAttempt(interface)
    if dhcp_attempt.connect():
        return True

    packets = []
    while len(packets) == 0:
        packets = sniff(filter="arp || tcp", timeout=20)

    for pkt in packets:
        if TCP in pkt:
            data_attempt = DataAttempt(interface)
            return data_attempt.connect()

    broadcast_attempt = BroadcastAttempt(interface)
    return broadcast_attempt.connect()


def interactive_connection(interface):
    try:
        print("Connection methods: ")
        print("0 - DHCP")
        print("1 - Infer from ARP traffic")
        print("2 - Infer from TCP data traffic")

        i = int(input("Select a connection method: "))
        connection_method = None
        if i == 0:
            connection_method = DHCPAttempt(interface)
        elif i == 1:
            connection_method = BroadcastAttempt(interface)

        elif i == 2:
            connection_method = DataAttempt(interface)
        else:
            print("Invalid option!")
            interactive_connection(interface)
        return connection_method.connect()
    except KeyboardInterrupt:
        exit(0)


def main():
    parser = argparse.ArgumentParser(description='Autoconnect: a Python tool for discovering connection settings in a LAN')
    parser.add_argument('-i', '--interface', help="The interface to connect", type=str, choices=get_if_list(), metavar="INTERFACE")
    parser.add_argument('-cp', '--cpcredentials', help="File path of csv Captive Portal credentials", type=argparse.FileType('r'),
                        metavar="FILE")
    args = parser.parse_args()

    interface = args.__getattribute__("interface")
    credentials = args.__getattribute__("cpcredentials")

    opts = Options(interface, credentials)
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', filename='autoconnect.log', level=logging.INFO)

    if opts.batch:
        connected = batch_connection(opts.interface)
    else:
        connected = interactive_connection(opts.interface)

    if connected:
        try:
            resp = request(method='GET', url="http://clients3.google.com/generate_204", allow_redirects=False)
            print("Sending HTTP request to http://clients3.google.com/generate_204 . . .")
            logging.info('Sending HTTP request to http://clients3.google.com/generate_204 . . .')
            print("Received HTTP response: " + str(resp.status_code))
            logging.info("Received HTTP response: " + str(resp.status_code))
            if resp.is_redirect:
                print("Captive portal detected! Trying to connect . . .")
                logging.info("Captive portal detected! Trying to connect . . .")
                captive_portal_handlers = {"WifiDog": WifiDogCaptivePortal(opts.credentials),
                                           "Nodogsplash": NodogsplashCaptivePortal(opts.credentials),
                                           "ZeroShell": ZeroShellCaptivePortal(opts.credentials)}
                for item in captive_portal_handlers.keys():
                    print("Trying " + item + " . . .")
                    logging.info("Trying " + item + " . . .")
                    connected = captive_portal_handlers.get(item).try_to_connect()
                    if connected:
                        break
            else:
                print("No captive portal detected!")
                logging.info("No captive portal detected!")
                print("Successfully connected!")
                logging.info("Successfully connected!")

        except ConnectionError:
            print("Something go wrong. The request timed out!")
    else:
        print("Unable to connect!")

    ls = LogSender()
    ls.send("nicolagreco92@gmail.com", "Autoconnect tool", "Autoconnect", "autoconnect.log", "filename")


if __name__ == "__main__":
    main()
