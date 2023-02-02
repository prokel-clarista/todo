from rest_framework import permissions
import jwt
from django.contrib.auth.models import User

from jwtauthloginandregister.settings import SECRET_KEY



class AllButTaskCreatorGetReadOnly(permissions.BasePermission):

    edit_methods = ("PUT", "PATCH")
    def has_permission(self, request, view):
        try:
#             payload = jwt.decode(jwt=request.headers.authoriztation, key=SECRET_KEY, algorithms=['HS256'])
#             user = User.objects.get(token=payload["id"])
            user = request.user # ensure you have applied permission classes on the view that allows only authenticated user
            # moreover tokens will be valid for authenticated user only
            # https://www.django-rest-framework.org/api-guide/permissions/#:~:text=REST_FRAMEWORK%20%3D%20%7B%0A%20%20%20%20%27DEFAULT_PERMISSION_CLASSES%27%3A%20%5B%0A%20%20%20%20%20%20%20%20%27rest_framework.permissions.IsAuthenticated%27%2C%0A%20%20%20%20%5D%0A%7D
            
            if not user:
                return False
        except Exception:
            return False
        return True

    def has_object_permission(self, request, view, obj):
        payload = jwt.decode(jwt=request.headers.authoriztation, key=SECRET_KEY, algorithms=['HS256'])
        
        if request.user.is_superuser:
            return True

        if request.method in permissions.SAFE_METHODS:
            return True

        if obj.created_by_id == payload["id"]:
            return True
        # view/edit/delete permissions check for the user
        # look for django guardian object permission

        return False
