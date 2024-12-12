from django.db import models
from django.contrib import admin
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import BaseUserManager

class CustomUserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        """Create and return a regular user with an email and password."""
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        """Create and return a superuser with an email, password, and other fields."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_admin', True)

        return self.create_user(username, email, password, **extra_fields)

class CustomUser(AbstractUser):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('user', 'User'),
    ]
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')

    # Use CustomUserManager for creating and managing users
    objects = CustomUserManager()

class Slots(models.Model):
    SlotID = models.AutoField(primary_key=True)  # Unique identifier for slots
    space = models.CharField(max_length=30, null=True, blank=True)
    price = models.IntegerField(null=True, blank=True)
    total_slots = models.IntegerField(default=90)

class Vehicle(models.Model):
    VehicleID = models.AutoField(primary_key=True)  # Unique identifier for vehicles
    SNo = models.BigIntegerField(unique=True)  # References the user's SNo
    VehicleType = models.CharField(max_length=40, null=True, blank=True)
    VehicleNumber = models.CharField(max_length=40, null=True, blank=True)
    VehicleName = models.CharField(max_length=40, null=True, blank=True)

class BookingSlot(models.Model):
    BSlotID = models.AutoField(primary_key=True)  # Explicit primary key for booking slots
    SNo = models.BigIntegerField(unique=True)  # References the user's SNo
    SlotID = models.ForeignKey(Slots, to_field="SlotID", on_delete=models.CASCADE)  # References the slot
    Date = models.DateField(null=True, blank=True)
    TimeFrom = models.TimeField(null=True, blank=True)
    TimeTo = models.TimeField(null=True, blank=True)
    duration = models.CharField(max_length=30, null=True, blank=True)
    VehicleID = models.ForeignKey(Vehicle, to_field="VehicleID", on_delete=models.CASCADE)  # References the vehicle

class Payment(models.Model):
    PaymentID = models.AutoField(primary_key=True)  # Unique identifier for payments
    SNo = models.BigIntegerField(unique=True)  # References the user's SNo
    BSlotID = models.ForeignKey(BookingSlot, to_field="BSlotID", on_delete=models.CASCADE)  # References the booking slot
    TotalPrice = models.IntegerField(null=True, blank=True)
    mode = models.CharField(max_length=30, null=True, blank=True)