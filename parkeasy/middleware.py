from datetime import timedelta
from django.http import JsonResponse
from django.utils.timezone import now, make_aware, is_naive

class CheckLastActiveMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            last_active = request.user.last_active

            # Make `last_active` timezone-aware if needed
            if last_active and is_naive(last_active):
                last_active = make_aware(last_active)

            # Check for inactivity (more than 1 minute)
            if last_active and now() - last_active > timedelta(minutes=1):
                return JsonResponse({"message": "You are inactive. Please log in again."}, status=401)

            # Update `last_active` to the current time
            request.user.last_active = now()
            request.user.save()

        response = self.get_response(request)
        return response
