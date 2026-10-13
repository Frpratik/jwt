"""
==============================================================================
 JWT IN DRF (function-based views)  -  WAY 2:  PyJWT   (you do it by hand)
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

 WHAT PyJWT DOES / DOESN'T DO
   PyJWT only has TWO functions:  jwt.encode()  and  jwt.decode().
   Everything else you write yourself:
     - the payload (who, expiry, which kind of token)
     - a helper to create tokens
     - a helper to check tokens
     - a decorator that runs the check before a protected view

 SETUP (3 steps)
   1. pip install djangorestframework PyJWT
   2. paste the settings below into settings.py
   3. paste views.py and urls.py below into your app
==============================================================================
"""

# ==============================================================================
# FILE: settings.py
# ==============================================================================
INSTALLED_APPS += ["rest_framework"]      # (add it to your existing INSTALLED_APPS list)

JWT_SECRET = SECRET_KEY                   # the signing key. Use a separate secret in production.

REST_FRAMEWORK = {
    # We check the token ourselves (the @jwt_required decorator below),
    # so we tell DRF not to run any authentication of its own.
    "DEFAULT_AUTHENTICATION_CLASSES": [],
}


# ==============================================================================
# FILE: views.py
# ==============================================================================
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt                                   # <- the PyJWT package
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from rest_framework.decorators import api_view
from rest_framework.response import Response

User = get_user_model()


# ---- 1. CREATE a token -------------------------------------------------------
def create_token(user, token_type, lifetime):
    now = datetime.now(timezone.utc)
    payload = {                       # the "claims": facts written INSIDE the token
        "sub": str(user.id),          # subject = who it is for (must be a string)
        "type": token_type,           # "access" or "refresh" so one can't pose as the other
        "exp": now + lifetime,        # expires at. After this the token is dead.
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")   # write + sign


# ---- 2. CHECK a token --------------------------------------------------------
def decode_token(token, expected_type):
    """Returns the payload if the token is good, otherwise None."""
    try:
        # decode = verify the signature AND the expiry, then give back the payload.
        # ALWAYS pass algorithms=[...]. It blocks a famous attack ("alg: none").
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:     # fake, edited, garbage, or expired
        return None
    if payload.get("type") != expected_type:      # e.g. a refresh token used as an access token
        return None
    return payload


# ---- 3. A DECORATOR that protects a view -------------------------------------
def jwt_required(view):
    """Put this above any view that needs a logged-in user."""
    @wraps(view)
    def wrapper(request, *args, **kwargs):
        # The header looks like:   Authorization: Bearer eyJhbGciOi...
        scheme, _, token = request.headers.get("Authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            return Response({"detail": "Send:  Authorization: Bearer <token>"}, status=401)

        payload = decode_token(token, "access")           # only ACCESS tokens allowed here
        if payload is None:
            return Response({"detail": "Invalid or expired token."}, status=401)

        try:
            request.user = User.objects.get(pk=payload["sub"])   # "sub" holds the user id
        except User.DoesNotExist:
            return Response({"detail": "User not found."}, status=401)

        return view(request, *args, **kwargs)             # token is good, run the real view
    return wrapper


# ---- 4. THE VIEWS ------------------------------------------------------------
@api_view(["POST"])
def login(request):
    # authenticate() checks the password. It returns None if wrong.
    user = authenticate(username=request.data.get("username"),
                        password=request.data.get("password"))
    if user is None:
        return Response({"detail": "Wrong username or password."}, status=401)

    return Response({
        "access": create_token(user, "access", timedelta(minutes=15)),
        "refresh": create_token(user, "refresh", timedelta(days=7)),
    })


@api_view(["POST"])
def refresh_token(request):
    payload = decode_token(request.data.get("refresh", ""), "refresh")   # must be a REFRESH token
    if payload is None:
        return Response({"detail": "Invalid or expired refresh token."}, status=401)

    user = User.objects.filter(pk=payload["sub"]).first()
    if user is None:
        return Response({"detail": "User not found."}, status=401)
    return Response({"access": create_token(user, "access", timedelta(minutes=15))})


@api_view(["GET"])
@jwt_required                       # <- "check the token first". Compare with SimpleJWT: it is automatic there.
def profile(request):
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
#   payload is readable by anyone (paste a token into jwt.io): {"sub": "1", "type": "access", "exp": ...}
#   signature proves nobody edited it. So NEVER put secrets inside a token.
#
# THE KEY DIFFERENCE FROM SimpleJWT (see the other file)
#   PyJWT:      create ->  jwt.encode(payload, secret, algorithm)  (you build the payload)
#               check  ->  jwt.decode(token, secret, algorithms)   (you call it yourself)
#   SimpleJWT:  create ->  RefreshToken.for_user(user)
#               check  ->  automatic, via JWTAuthentication in settings.py
#
# NO LOGOUT HERE: a JWT can't be deleted from the server. To support logout you
# must store cancelled refresh tokens (their "jti" id) in a database table and
# reject them in refresh_token(). SimpleJWT's blacklist app does exactly that.
# ==============================================================================