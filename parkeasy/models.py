from django.db import models

# class User(models.Model):
#     SNo = models.AutoField(primary_key=True)  # Unique identifier for the user
#     username = models.CharField(max_length=255, null=True, blank=True)
#     email = models.EmailField(unique=True, max_length=255)
#     password = models.CharField(max_length=255, null=True, blank=True)
#     role = models.CharField(max_length=40, default='user')

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