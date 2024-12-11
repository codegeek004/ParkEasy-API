from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin

class UserManager(BaseUserManager):
	def create_user(self, email, name, tc, password=None, passwor2=None):
		print('create user mai gaya')
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
		print('user ke niche')
		user.set_password(password)
		#saves into a database instance
		print('user.save ke upar UserManager mau')
		user.save(using=self._db)
		return user

	def create_superuser(self, email, name, tc, password=None, passwor2=None):
		print('create superuser mai gaya')
		if not email:
			raise ValueError("You must have an email address")
		user = self.create_user(
				email,
				password=password,
				name=name,
				tc=tc 
			)
		print('user ke niche')
		user.is_admin=True 
		print('user.is_admin', user.is_admin)
		user.is_superuser=True 
		user.is_staff = True
		user.save(using=self._db)
		return user
	
class User(AbstractBaseUser, PermissionsMixin):
	email = models.EmailField(verbose_name="email", max_length=255, unique=True)
	name = models.CharField(max_length=255, blank=True)
	tc = models.BooleanField()
	is_active = models.BooleanField(default=True)
	is_admin = models.BooleanField(default=False)
	is_staff = models.BooleanField(default=False)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	objects = UserManager()

	USERNAME_FIELD = "email"
	REQUIRED_FIELDS = ["name","tc"]

	def __str__(self):
		return f"{self.email} {self.name}"



