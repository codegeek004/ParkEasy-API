# Generated by Django 5.1.4 on 2024-12-18 12:16

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('parkeasy', '0005_customuser_is_2fa_enabled'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='remember_me',
            field=models.BooleanField(default=False),
        ),
    ]
