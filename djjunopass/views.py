from django.shortcuts import (render, redirect)
from django.template import loader
from django.conf import settings
from django.http import HttpResponse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login
from django.contrib.auth import logout
from django.urls import resolve
import datetime
import pytz

from junopass import JunoPass

from .forms import AuthForm, VerifyForm

jp = JunoPass(settings.JUNOPASS_ACCESS_TOKEN,
              settings.JUNOPASS_PUBLIC_KEY, settings.JUNOPASS_PROJECT_ID)


def set_cookie(response, key, value, days_expire=30):
    """
    Set django cookies
    """
    # Set max age to 1 year as default
    max_age = 365 * 24 * 60 * 60
    if days_expire:
        max_age = days_expire * 24 * 60 * 60
    expires = datetime.datetime.strftime(datetime.datetime.utcnow(
    ) + datetime.timedelta(seconds=max_age), "%a, %d-%b-%Y %H:%M:%S GMT")
    response.set_cookie(key, value, max_age=max_age, expires=expires,
                        domain=settings.SESSION_COOKIE_DOMAIN, secure=settings.SESSION_COOKIE_SECURE or None, httponly=settings.SESSION_COOKIE_HTTPONLY, samesite=settings.SESSION_COOKIE_SAMESITE)


def render_response(request, template_name, device_private_key, device_public_key, context={}, status=200):
    content = loader.render_to_string(template_name, context, request)
    response = HttpResponse(content, status=status)
    if not (device_private_key and device_public_key):
        # Set the device keys
        private_key_name = settings.JUNOPASS_DEVICE_PRIVATE_KEY_NAME
        public_key_name = settings.JUNOPASS_DEVICE_PUBLIC_KEY_NAME

        private_key, public_key = jp.setup_device()
        set_cookie(response, private_key_name, private_key)
        set_cookie(response, public_key_name, public_key)
    return response


def login_view(request):
    """
    STEP 1: Authenticate user.
    """
    try:
        device_public_key = request.COOKIES.get(
            settings.JUNOPASS_DEVICE_PUBLIC_KEY_NAME)
        device_private_key = request.COOKIES.get(
            settings.JUNOPASS_DEVICE_PRIVATE_KEY_NAME)
        project_id = settings.JUNOPASS_PROJECT_ID
        access_token = settings.JUNOPASS_ACCESS_TOKEN

        next_url = request.GET.get("next", None)
        form = AuthForm(request.POST or None)
        if request.method == "POST":
            # Implement step 1 request
            if form.is_valid():
                identifier = form.cleaned_data["identifier"]

                valid_challenge, device_id, login_request = jp.authenticate(
                    "EMAIL", identifier, device_public_key)
                if login_request:
                    result = jp.verify(
                        valid_challenge, device_id, device_private_key)

                    # Add user in the database and activate session
                    identifier = result.get("identifier")
                    user = authenticate(request, identifier=identifier)
                    if not user:
                        raise Exception("Could not login user")

                    login(request, user)
                    return redirect(next_url or settings.LOGIN_REDIRECT_URL)
                else:
                    request.session["djjunopass_challenge"] = valid_challenge
                    request.session["djjunopass_device_id"] = device_id
                    return redirect("djjunopass:verify")
                # End authorization

                # Template response
        context = {'form': form}
        return render_response(request, "djjunopass/login.html", device_private_key, device_public_key, context)
    except Exception as ex:
        form = AuthForm(request.POST or None)
        messages.error(request, str(ex))
        return render(request, "djjunopass/login.html", {"form": form})


def verify_view(request):
    """
    STEP 2: Verify OTP
    """
    try:
        device_public_key = request.COOKIES.get(
            settings.JUNOPASS_DEVICE_PUBLIC_KEY_NAME)
        device_private_key = request.COOKIES.get(
            settings.JUNOPASS_DEVICE_PRIVATE_KEY_NAME)

        print(f"Session: {request.session.__dict__}")
        challenge = request.session.get("djjunopass_challenge")
        device_id = request.session.get("djjunopass_device_id")
        next_url = request.GET.get("next", None)

        print(f"Challenge: {challenge}")
        print(f"Device id:{device_id}")

        form = VerifyForm(request.POST or None)
        if request.method == "POST":
            if form.is_valid():
                otp = form.cleaned_data["otp"]
                result = jp.verify(
                    challenge, device_id, device_private_key, otp)

                # Add user in the database and activate session
                identifier = result.get("identifier")
                user = authenticate(request, identifier=identifier)
                if not user:
                    raise Exception("Could not login user")

                login(request, user)
                return redirect(next_url or settings.LOGIN_REDIRECT_URL)
        return render(request, "djjunopass/verify.html", {"form": form})
    except Exception as ex:
        form = VerifyForm(request.POST or None)
        messages.error(request, str(ex))
        return render(request, "djjunopass/verify.html", {"form": form})


@login_required
def logout_view(request):
    """
    Logout user
    """
    logout(request)
    return redirect("junopass:login")
