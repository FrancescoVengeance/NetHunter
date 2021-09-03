from django.shortcuts import render
from naspy.Naspy import Naspy


def index_view(request, *args, **kwargs):
    context = {}
    return render(request, "index.html", context)


def run(request, *args, **kwargs):
    if request.method == "POST":
        naspy = Naspy()
        print("Start sniffing")
        naspy.sniff("enp0s3")
