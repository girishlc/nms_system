# dashboard/urls.py

from django.urls import path
from .views import dns_view, add_dns, delete_dns

urlpatterns = [
    path("", dns_view, name="dns_view"),
    path("add_dns/", add_dns, name="add_dns"),
    path("delete_dns/<str:dns_id>/", delete_dns, name="delete_dns"),
]
