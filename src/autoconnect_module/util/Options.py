from scapy.arch.linux import _get_if_list


class Options:
    def __init__(self, interface, credentials):
        self.interface = interface
        self.credentials = None
        self.batch = True
        if credentials is not None:
            self.credentials = credentials.name
        if interface is None:
            self.set_interface()
            self.batch = False

    def set_interface(self):
        try:
            interfaces = _get_if_list()
            print("Available interfaces: ")
            for i in range(0, len(interfaces)):
                print(str(i) + " - " + interfaces[i])

            i = int(input("Select an interface to connect: "))
            if 0 <= i < len(interfaces):
                self.interface = str(interfaces[i])
            else:
                print("Invalid option!")
                self.set_interface()
        except KeyboardInterrupt:
            exit(0)
