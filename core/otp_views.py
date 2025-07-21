

# Django core imports
from django import forms
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import (
    authenticate, 
    get_user_model, 
    login, 
    logout, 
    update_session_auth_hash
)
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.signals import user_logged_in
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.core.validators import validate_email
from django.db import IntegrityError, transaction
from django.dispatch import receiver
from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.utils import timezone

# Third-party libraries
from email_validator import validate_email as email_validate, EmailNotValidError
from datetime import timedelta
import phonenumbers
import re
import string as st
import threading
# Project-specific imports
from .models import OTPLog, LoginAttempt, SecurityLog, Profile, CustomUser, OTPSetting
from .utils import generate_otp, send_otp_via_email, send_otp_via_whatsapp
from .forms import CustomPasswordChangeForm

def resend_otp_view(request):
    otp = generate_otp()
    request.session['login_otp'] = otp
    phone_number = request.user.phone.lstrip('0')
    try:
        send_otp_via_whatsapp(phone_number, otp)
        #Logs
        OTPLog.objects.create(
            user=request.user,
            code=otp,
            purpose='login',
            send_via='WhatsApp',
            expires_at=timezone.now() + timezone.timedelta(minutes=10)
        )
        messages.success(request, f"OTP re-sent to WhatsApp {phone_number}")
    except Exception as e:
        messages.error(request, f"Failed to re-send OTP: {e}") 
    return redirect("verify-login")
#from login page reset password hyperlink
def select_reset_method_view(request):
    return render(request, 'core/select-reset-method.html')







