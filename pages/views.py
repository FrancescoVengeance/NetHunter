from django.shortcuts import render
from naspy.Naspy import Naspy


def index_view(request, *args, **kwargs):
    naspy = Naspy()
    print("Start sniffing")
    naspy.sniff("enp0s3")
    context = {}
    return render(request, "index.html", context)


def run(request, *args, **kwargs):
    print(f"metodo chiamato {request.method}")
    if request.method == "POST":
        naspy = Naspy()
        print("Start sniffing")
        naspy.sniff("enp0s3")
