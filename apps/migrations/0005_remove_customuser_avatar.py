# Generated by Django 4.2 on 2024-06-25 03:20

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('apps', '0004_hostmonitoring_host_encryption_key'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='customuser',
            name='avatar',
        ),
    ]
