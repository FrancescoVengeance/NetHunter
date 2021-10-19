from django.shortcuts import render
from src.naspy import Naspy


def index_view(request, *args, **kwargs):
    context = {}
    if request.method == "GET":
        return render(request, "index.html", context)
    elif request.method == "POST":
        naspy = Naspy()
        print("Start sniffing")
        naspy.sniff("enp0s3")
        return render(request, "index.html", context)
