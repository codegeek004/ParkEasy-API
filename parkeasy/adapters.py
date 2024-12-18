from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from rest_framework_simplejwt.tokens import RefreshToken
from django.http import JsonResponse

######################AllAuth###########################

class CustomGoogleAccountAdapter(DefaultSocialAccountAdapter):
    
    def pre_google_login(self, request, socialaccount):

        user = socialaccount.user  
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        response_data = {
            "access_token" : access_token,
            "refresh_token" : refresh_token
        }

        print(f"access_token: {access_token}")
        print(f"refrehs_token: {refresh_token}")

        return Response(response_data)

####################Allauth end##########################