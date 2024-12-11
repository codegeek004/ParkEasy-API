from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser

class UserManager(BaseUserManager):
	def create_user(self, email, name, tc, password=None, passwor2=None):
		"""
		creates and saves the user with email, name, tc and password
		"""
		if not email:
			raise ValueError("You must have an email address")

		user = self.model(
				email = self.normalize_email(email),
				name = name,
				tc=tc
			)
		user.save_password(password)
		#saves into a database instance
		user.save(using=self._db)

	def create_superuser(self, email, name, tc, password=None, passwor2=None):
		if not email:
			raise ValueError("You must have an email address")
		user = self.create_user(
				email,
				password=password,
				name=name,
				tc=tc 
			)
		user.is_admin=True 
		user.save(using=self._db)
		return user

class User(AbstractBaseUser):
	email = models.EmailField(verbose_name="email", max_length=255, unique=True)
	tc = models.BooleanField()
	is_active = models.BooleanField(default=True)
	is_admin = models.BooleanField(default=False)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	objects = UserManager()

	USERNAME_FIELD = "email"
	REQUIRED_FIELDS = ["name","tc"]

	def __str__(self):
		return self.email 

	



