# Generated by Django 5.1.4 on 2024-12-17 06:59

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('parkeasy', '0003_customuser_mfa_enabled_customuser_mfa_secret'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='customuser',
            name='mfa_enabled',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='mfa_secret',
        ),
    ]
