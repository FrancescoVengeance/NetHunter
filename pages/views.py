from django.shortcuts import render


def index_view(request, *args, **kwargs):
    context = {}
    return render(request, "index.html", context)
