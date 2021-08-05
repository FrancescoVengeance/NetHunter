from Naspy import Naspy

if __name__ == "__main__":

    naspy = Naspy()
    await naspy.sniff("eth0")

    for element in naspy.manager.visited:
        print(element.hostname)
