from django.utils.timezone import now
from rest_framework_simplejwt.tokens import RefreshToken
from .models import ActiveToken
class PreventConcurrentLoginMiddleware:
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = request.user
        if user.is_authenticated:
            try:
                active_token = ActiveToken.objects.get(user=request.user)
                old_token = RefreshToken(active_token.refresh_token)
                print('active_token', active_token)
                print('old token', old_token)
                old_token.blacklist()
                active_token.delete()
            except ActiveToken.DoesNotExist:
                pass

            refresh = RefreshToken.for_user(request.user)
            request.user.last_active = now()
            request.user.latest_token = refresh.access_token['jti']
            request.user.save()

            ActiveToken.objects.create(
                    user = request.user,
                    refresh_token=str(refresh),
                )
        response = self.get_response(request)
        return response