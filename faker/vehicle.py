import random
from faker import Faker
import pymysql

# Initialize Faker
fake = Faker()

# Indian vehicle names for cars, bikes, and heavy vehicles
vehicle_names = [
    "Maruti Suzuki", "Hyundai", "Mahindra", "Tata Motors", "Honda", "Bajaj", "Hero", "Royal Enfield", "Ashok Leyland", "Eicher"
]

# Connect to the database
connection = pymysql.connect(
    host='localhost',  # Change this to your DB host
    user='root',       # Change this to your DB username
    password='root',  # Change this to your DB password
    database='parkeasy',  # Change this to your DB name
)

cursor = connection.cursor()

# SQL Insert Statement
insert_query = """
INSERT INTO parkeasy_vehicle (VehicleType, VehicleNumber, VehicleName, SNo)
VALUES (%s, %s, %s, %s)
"""

# Generate and insert 100 entries
for i in range(1, 101):
    vehicle_type = random.choice(["car", "bike", "heavy vehicle"])
    vehicle_number = f"{random.choice(['MP', 'MH', 'DL', 'KA', 'UP'])}{random.randint(1, 99):02d}{random.choice(['AA', 'AB', 'VF', 'ZX', 'KL'])}{random.randint(1000, 9999)}"
    vehicle_name = random.choice(vehicle_names)
    sno = i  # SNo should be unique

    # Execute the insert query
    cursor.execute(insert_query, (vehicle_type, vehicle_number, vehicle_name, sno))

# Commit the transaction and close the connection
connection.commit()
cursor.close()
connection.close()

print("100 vehicle entries inserted successfully!")

