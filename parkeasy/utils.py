from calendar import timegm
from datetime import datetime
from rest_framework_jwt.compat import get_username, get_username_field
from rest_framework_simplejwt.settings import api_settings
from django_otp.models import Device

def jwt_otp_payload(user, device=None):
	#optionally include otp device in jwt payload
	username_field = get_username_field()
	username = get_username(user)

	payload = {
		"user_id" : user.pk,
		"username" : username,
		"exp" : datetime.utcnow + api_settings.JWT_EXPIRATION_DELTA
	}