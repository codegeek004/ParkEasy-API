"""
Django settings for parking project.

Generated by 'django-admin startproject' using Django 5.1.4.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.1/ref/settings/
"""

from pathlib import Path
from datetime import timedelta
from decouple import config
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-l%6bb&g@$a$%5od79jg+0cq*kiykd0740(vv2f8t6hv1m1@4f+'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    #my apps
    'parkeasy',
    'rest_framework_simplejwt',
    'rest_framework',
    'rest_framework_roles', 
    'rest_framework_simplejwt.token_blacklist',
    #all auth
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.github',
    'allauth.socialaccount.providers.google',
    'rest_framework.authtoken',
    'dj_rest_auth',
    #multi-factor authentication
    'django_otp',
    'django_otp.plugins.otp_totp'
]
    
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    # allauth   
    "allauth.account.middleware.AccountMiddleware",
    #my middlewares
    'parkeasy.middleware.PreventConcurrentLoginMiddleware',
]

ROOT_URLCONF = 'parking.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'parking.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'parkeasy',
        'HOST':'localhost',
        'USER':'root',
        'PASSWORD':'root',
        'PORT':3306
    }
}

# SOCIALACCOUNT_PROVIDERS = {
#     'google': {
#         'SCOPE': ['profile', 'email'],
#         'AUTH_PARAMS': {'access_type': 'online'},
#         'APP': {
#             'client_id': '99034799467-hl9dbl4t4l64gftesd8bokb1no6kbgu3.apps.googleusercontent.com',
#             'secret': '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',
#             'key': '',
# #         }
#     }
# }
SOCIALACCOUNT_ADAPTER = 'parkeasy.adapters.CustomGoogleAccountAdapter'

SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'SCOPE': ['profile', 'email'],
        'AUTH_PARAMS': {'access_type': 'online'},
        'OAUTH_PKCE_ENABLED': True,
        'APP': {
            'client_id': '99034799467-hl9dbl4t4l64gftesd8bokb1no6kbgu3.apps.googleusercontent.com',
            'secret': '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',
            'key': 'google',
        },
    }
}



# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]



AUTHENTICATION_BACKENDS = [

    # Needed to login by username in Django admin, regardless of `allauth`
    'django.contrib.auth.backends.ModelBackend',

    # `allauth` specific authentication methods, such as login by email
    'allauth.account.auth_backends.AuthenticationBackend',
    #remember me
    # 'auth_remember.backend.AuthRememberBackend',

]


# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Kolkata'

USE_I18N = True

USE_TZ = True

LOGIN_REDIRECT_URL = '/protected'

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# AUTH_USER_MODEL = 'parkeasy.CustomUser'

#Simplejwt configurations
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    # 'DEFAULT_RENDERER_CLASSES': [
    #     'rest_framework.renderers.JSONRenderer',  # This avoids looking for templates
    # ],

}
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME" : timedelta(minutes=10),
    "RERESH_TOKEN_LIFETIME" : timedelta(days=1),
    "ROTATE_REFRESH_TOKENS": True,  
    "BLACKLIST_AFTER_ROTATION": True,   
    "AUTH_HEADER_TYPES": ("Bearer",),
}


# Allauth Settings
ACCOUNT_EMAIL_REQUIRED = False  # Do not require email for registration
ACCOUNT_USERNAME_REQUIRED = True  # Enforce username as required field
ACCOUNT_EMAIL_VERIFICATION = 'none'  # Disable email verification
SOCIALACCOUNT_EMAIL_REQUIRED = False  # Do not require email during social login
SOCIALACCOUNT_USERNAME_REQUIRED = True  

REST_FRAMEWORK_ROLES = {
    'ROLES': 'myproject.roles.ROLES',  # Replace with your actual path to roles
    'SKIP_MODULES': [
        'django.*',
        'allauth.*',
        'django_otp.*',

    ],
}

ROLES = {
    'admin': ['can_view', 'can_edit', 'can_delete'],
    'user': ['can_view'],
}
AUTH_USER_MODEL = "parkeasy.CustomUser"



#SMTP configurations

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = config("EMAIL_HOST", cast=str, default="yashvaishnav1411@gmail.com")
EMAIL_PORT = config("EMAIL_PORT", cast=str, default="587")
EMAIL_USE_TLS=True
EMAIL_HOST_USER = config("EMAIL_HOST_USER", cast=str, default=None)
EMAIL_HOST_PASSWORD = config("EMAIL_HOST_PASSWORD", cast=str, default=None)
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER
PASSWORD_RESET_BASE_URL = config('PASSWORD_RESET_BASE_URL', cast=str, default='http://127.0.0.1:8000/password/reset')



CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',  # Redis URL
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}

