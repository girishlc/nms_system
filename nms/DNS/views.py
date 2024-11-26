from django.shortcuts import render, redirect, get_object_or_404
from .models import DNS
import logging

logger = logging.getLogger(__name__)


# Create your views here.
def dns_view(request):
    get_saved_dns = DNS.objects.values("dns_name", "dns_created_at")
    if get_saved_dns:
        context = {"dns_id": get_saved_dns}
        return render(request, "dns.html", context)
    return render(request, "dns.html")


def add_dns(request):
    if request.POST:
        get_dns_id = request.POST.get("dns_address")
        DNS.objects.create(dns_name=get_dns_id)
    return redirect("dns_view")


def delete_dns(request, dns_id):
    # Fetch the DNS object by its ID
    dns = get_object_or_404(DNS, dns_name=dns_id)

    # Delete the DNS record
    dns.delete()

    # Redirect back to the DNS page
    return redirect("dns_view")
