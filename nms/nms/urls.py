from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("USER.urls")),  # Include the login app URLs
    path("dashboard/", include("DASHBOARD.urls")),
    path("dns/", include("DNS.urls")),
]
