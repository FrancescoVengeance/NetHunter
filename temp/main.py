from Naspy import Naspy


async def sniff():
    naspy = Naspy()
    await naspy.sniff("eth0")


if __name__ == "__main__":

    sniff()
