# Generated by Django 5.1.4 on 2024-12-15 12:32

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('parkeasy', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='last_active',
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now, null=True),
        ),
    ]