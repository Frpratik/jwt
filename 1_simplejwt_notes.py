"""
==============================================================================
 JWT IN DRF (function-based views)  -  WAY 1:  djangorestframework-simplejwt
==============================================================================
 IDEA IN ONE LINE
   After login the server gives the user a signed "token". The user sends that
   token with every request as proof of who they are. The server stores nothing.

 TWO TOKENS
   access token   short life (15 min)  -> sent with every request
   refresh token  long life  (7 days)  -> used ONLY to get a new access token

 FLOW
   1. login      POST /api/login/          {username, password}  ->  {access, refresh}
   2. API call   GET  /api/profile/        Authorization: Bearer <access>  ->  200
   3. 15 min later the access token is dead -> API says 401
   4. refresh    POST /api/token/refresh/  {refresh}             ->  {access}
   5. refresh token dead too -> log in again

 WHAT SimpleJWT DOES FOR YOU
   - creates tokens        ->  RefreshToken.for_user(user)
   - checks tokens         ->  automatically, on EVERY request, through DRF's
                               authentication class (set once in settings.py)
 So your protected views contain ZERO token code.

 SETUP (3 steps)
   1. pip install djangorestframework djangorestframework-simplejwt
   2. paste the settings below into settings.py
   3. paste views.py and urls.py below into your app
==============================================================================
"""

# ==============================================================================
# FILE: settings.py
# ==============================================================================
from datetime import timedelta

INSTALLED_APPS += ["rest_framework"]      # (add it to your existing INSTALLED_APPS list)

REST_FRAMEWORK = {
    # "Check every request for a JWT in the header  Authorization: Bearer <token>"
    # If the token is good, DRF sets request.user. If bad or expired -> 401.
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ],
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=15),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
}
# Tokens are signed with Django's SECRET_KEY, so keep SECRET_KEY private.


# ==============================================================================
# FILE: views.py
# ==============================================================================
from django.contrib.auth import authenticate
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken


@api_view(["POST"])
@authentication_classes([])          # login can't require a token (you don't have one yet)
@permission_classes([AllowAny])
def login(request):
    # authenticate() checks the password. It returns None if wrong.
    user = authenticate(username=request.data.get("username"),
                        password=request.data.get("password"))
    if user is None:
        return Response({"detail": "Wrong username or password."}, status=401)

    refresh = RefreshToken.for_user(user)          # <- SimpleJWT creates the token
    return Response({
        "access": str(refresh.access_token),       # the short-lived token
        "refresh": str(refresh),                   # the long-lived token
    })


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
def refresh_token(request):
    try:
        refresh = RefreshToken(request.data.get("refresh", ""))   # <- SimpleJWT checks it
    except TokenError:                                            # expired / fake / wrong kind
        return Response({"detail": "Invalid or expired refresh token."}, status=401)
    return Response({"access": str(refresh.access_token)})        # a new access token


@api_view(["GET"])
@permission_classes([IsAuthenticated])   # "must be logged in". The token check already ran (settings.py)
def profile(request):
    # NO token code here. JWTAuthentication already verified the token
    # and put the user in request.user. If the token was bad, we never get here.
    return Response({"username": request.user.username, "email": request.user.email})


# ==============================================================================
# FILE: urls.py
# ==============================================================================
from django.urls import path

from . import views

urlpatterns = [
    path("api/login/", views.login),
    path("api/token/refresh/", views.refresh_token),
    path("api/profile/", views.profile),
]


# ==============================================================================
# TRY IT   (create a user first:  python manage.py createsuperuser)
# ==============================================================================
#   curl -X POST http://127.0.0.1:8000/api/login/ -H "Content-Type: application/json" ^
#        -d "{\"username\":\"ravi\",\"password\":\"yourpassword\"}"
#   curl http://127.0.0.1:8000/api/profile/ -H "Authorization: Bearer <access>"
#   (Mac/Linux: use \ instead of ^ at the end of a line)


# ==============================================================================
# WHAT IS INSIDE A TOKEN?   header . payload . signature
#   payload is readable by anyone (paste a token into jwt.io): {"user_id": 1, "exp": ...}
#   signature proves nobody edited it. So NEVER put secrets inside a token.
#
# THE KEY DIFFERENCE FROM PyJWT (see the other file)
#   SimpleJWT:  create ->  RefreshToken.for_user(user)
#               check  ->  automatic, via JWTAuthentication in settings.py
#   PyJWT:      create ->  jwt.encode(payload, secret, algorithm)  (you build the payload)
#               check  ->  jwt.decode(token, secret, algorithms)   (you call it yourself)
#
# NO LOGOUT HERE: a JWT can't be deleted from the server. To support logout you
# add "rest_framework_simplejwt.token_blacklist" to INSTALLED_APPS, run migrate,
# and call  RefreshToken(token).blacklist()  in a logout view.
# ==============================================================================