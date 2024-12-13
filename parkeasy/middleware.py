from datetime import timedelta
from django.utils.timezone import now

class CheckLastActiveMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            last_active = request.user.last_active
            if last_active and now() - last_active > timedelta(minutes=1):
                return JsonResponse({"message": "You are inactive. Please log in again."}, status=401)
            # Update the user's last_active field if they are active
            request.user.last_active = now()
            request.user.save()
        response = self.get_response(request)
        return response
