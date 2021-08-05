from Naspy import Naspy


async def sniff():
    naspy = Naspy()
    await naspy.sniff("eth0")


await sniff()
