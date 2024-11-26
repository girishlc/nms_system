from django.db import models


# Create your models here.
class DNS(models.Model):
    dns_name = models.CharField(max_length=50, blank=True)
    dns_created_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.dns_name
