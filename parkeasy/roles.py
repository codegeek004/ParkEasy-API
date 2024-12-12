from rest_framework_roles.roles import is_user, is_admin

ROLES = {
    # Django out-of-the-box
    'admin': is_admin,
    'user': is_user,
    'anon': is_anon,
    }

