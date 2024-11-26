# Generated by Django 4.2.6 on 2024-11-25 06:00

from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="DNS",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("dns_name", models.CharField(blank=True, max_length=50)),
                ("dns_created_at", models.DateTimeField(auto_now=True)),
            ],
        ),
    ]
