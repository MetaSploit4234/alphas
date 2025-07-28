# Django core imports
from django import forms
from datetime import timedelta
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate, get_user_model, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.signals import user_logged_in
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.core.validators import validate_email
from django.db import IntegrityError, transaction
from django.dispatch import receiver
from django.http import JsonResponse, request
from django.shortcuts import render, redirect, get_object_or_404
from django.utils import timezone
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST, require_http_methods
from django.utils.timezone import now
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.conf import settings
#python modules
from email_validator import validate_email as email_validate, EmailNotValidError
import phonenumbers
import re
import string as st
import threading
import io
import base64
from .utils import generate_otp, send_otp_via_email
import pyotp
import qrcode
import qrcode.image.svg
from io import BytesIO
# Project-specific imports
from .models import OTPLog, LoginAttempt, SecurityLog, Profile, CustomUser, OTPSetting
from .forms import CustomPasswordChangeForm
import logging

logger = logging.getLogger(__name__)

User = get_user_model()

def index_view(request):
    return render(request, 'core/index.html')  # Or your template path

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def get_device_info(request):
    return request.META.get("HTTP_USER_AGENT", "Unknown Device")

def send_signup_email_otp(user, email_otp):
    def send_email():
        try:
            subject = "Signup OTP"
            body = f"Hello {user.first_name},\nYour OTP is: {email_otp}\nIt expires in 10 minutes."
            send_otp_via_email([user.email], email_otp, subject=subject, body=body)
            print(f"[OTP SENT] Email OTP sent to {user.email}")
        except Exception as e:
            print(f"Failed to send email OTP: {e}")

    threading.Thread(target=send_email, daemon=True).start()

#Registration
logger = logging.getLogger(__name__)
#signup
@csrf_protect
@require_http_methods(["GET", "POST"])
def register_view(request):
    #http method check
    if request.method != 'POST':
        return render(request, 'core/register.html')
    # Honeypot check
    if request.POST.get("bot_catcher"):
        messages.error(request, "Suspicious activity detected.")
        return redirect("register")
    #obtain ip
    ip = get_client_ip(request)
    # Brute force protection
    if SecurityLog.objects.filter(
        ip_address=ip,
        event_type="Registration",
        timestamp__gte=timezone.now() - timezone.timedelta(minutes=5)
    ).count() >= 5:
        messages.error(request, "Too many signup attempts. Please wait a few minutes.")
        return render(request, 'core/access-denied.html')
    # Get form data
    first_name = request.POST.get("first_name", "").strip()
    last_name = request.POST.get("last_name", "").strip()
    email = request.POST.get("email", "").strip()
    phone = request.POST.get("phone", "").strip()
    password = request.POST.get("password", "")
    confirm_password = request.POST.get("confirm_password", "")
    # Validate required fields
    if not all([first_name, last_name, email, phone, password, confirm_password]):
        messages.error(request, "All fields are required.")
        return render(request, 'core/register.html')
    # Check if phone or email already exists
    if User.objects.filter(phone=phone).exists():
        messages.error(request, "Phone number already exists.")
        return render(request, 'core/register.html')

    if User.objects.filter(email=email).exists():
        messages.error(request, "Email already registered.")
        return render(request, 'core/register.html')
    # Validate email and phone number formats
    try:
        email = email_validate(email).email
    except EmailNotValidError:
        messages.error(request, "Invalid email address.")
        return render(request, 'core/register.html')

    try:
        parsed = phonenumbers.parse(phone, "KE")
        if not phonenumbers.is_valid_number(parsed):
            raise ValueError()
        formatted_phone = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    except Exception:
        messages.error(request, "Enter a valid Kenyan phone number.")
        return render(request, 'core/register.html')
    # Validate password strength
    if len(password) < 8:
        messages.error(request, "Password must be at least 8 characters.")
        return render(request, 'core/register.html')
    if password != confirm_password:
        messages.error(request, "Passwords do not match.")
        return render(request, 'core/register.html')
    if not (any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in st.punctuation for c in password)):
        messages.error(request, "Password must include uppercase, lowercase, digit, and symbol.")
        return render(request, 'core/register.html')
    # Create user and profile
    try:
        with transaction.atomic():
            user = User.objects.create_user(
                phone=formatted_phone,
                first_name=first_name,
                last_name=last_name,
                email=email,
                password=password,
                is_active=False
            )
            logger.info(f"User created with ID {user.id}")
            # Generate TOTP secret and save profile
            totp_secret = pyotp.random_base32()
            profile, _ = Profile.objects.get_or_create(user=user)
            profile.totp_secret = totp_secret
            profile.preferred_2fa_method = 'authenticator'
            profile.save()
            logger.info(f"Profile saved for user ID {user.id}")

            email_otp = generate_otp()
            expiry = timezone.now() + timezone.timedelta(minutes=10)
            OTPLog.objects.create(
                user=user,
                code=email_otp,
                purpose='signup',
                sent_via='email',
                expires_at=expiry
            )
            logger.info(f"OTPLog created for user ID {user.id}")
            # Log the registration event
            SecurityLog.objects.create(
                user=user,
                event_type="Registration",
                ip_address=ip,
                user_agent=get_device_info(request),
                details="New user registered with Authenticator TOTP."
            )
            # Generate QR code for TOTP setup
            totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
                name=user.email,
                issuer_name="MFA"
            )
            # Generate QR code as SVG
            buffer = BytesIO()
            qrcode.make(totp_uri, image_factory=qrcode.image.svg.SvgImage).save(buffer)
            request.session['totp_qr_svg'] = buffer.getvalue().decode()

            request.session['pending_user'] = formatted_phone
            request.session['pending_signup'] = True

            send_signup_email_otp(user, email_otp)
            logger.info("Signup OTP sent to email")
    #integrity error handling
    except IntegrityError as e:
        logger.error(f"IntegrityError: {e}")
        messages.error(request, "Registration failed due to a server error.")
        return render(request, 'core/register.html')
    #general exception handling
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        messages.error(request, "Registration failed due to a server error.")
        return render(request, 'core/register.html')

    messages.success(request, "Registration successful! Please verify your account.")
    return redirect('verify-signup')

#verify registration
@csrf_protect
@require_http_methods(["GET", "POST"])
def verify_signup_view(request):
    #get sessions
    phone = request.session.get('pending_user')
    pending = request.session.get('pending_signup')
    #check if useris pending in session
    if not request.user.is_authenticated:
        if not phone or not pending:
            messages.error(request, "Session expired. Please register again.")
            return redirect('register')
    #get user
    try:
        user = User.objects.get(phone=phone)
    except User.DoesNotExist:
        messages.error(request, "User not found.")
        return redirect('register')
    
    if request.method == 'POST':
        # Handle email OTP verification
        email_otp = request.POST.get('otp-email', '').strip()
        if not email_otp:
            messages.error(request, "Email OTP is required.")
            return render(request, 'core/verify-signup.html')
        e_otp = OTPLog.objects.filter(
            user=user, purpose='signup', sent_via='email', verified=False
        ).order_by('-created_at').first()
        if not e_otp:
            messages.error(request, "Email OTP not found or already verified.")
            return redirect('register')
        now = timezone.now()
        if e_otp.expires_at < now:
            messages.error(request, "Email OTP expired. Please register again.")
            return redirect('register')
        if email_otp != e_otp.code:
            messages.error(request, "Invalid Email OTP.")
            return render(request, 'core/verify-signup.html')
        # Mark OTP as verified
        e_otp.verified = True
        e_otp.verified_at = now
        e_otp.save()
        # Activate user account
        user.is_active = True
        user.save()
        # Log the signup verification event
        SecurityLog.objects.create(
            user=user,
            event_type="Signup Verified",
            ip_address=get_client_ip(request),
            user_agent=get_device_info(request),
            details="User verified via Email OTP."
        )
        # Store for next view
        request.session['setup_user_id'] = user.id
        # Add success message
        messages.success(request, "Email verified! Please set up your authenticator.")
        return redirect('setup-authenticator')
    return render(request, 'core/verify-signup.html')

#setup auth
def setup_authenticator_view(request):
    # Check if user is in pending session
    user_id = request.session.get('setup_user_id')
    if not user_id:
        messages.error(request, "Session expired or invalid flow. Please sign up again.")
        return redirect('register')
    User = get_user_model()
    # Fetch user by ID
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        messages.error(request, "User not found. Please start again.")
        return redirect('register')
    # Check if user already has authenticator setup
    if not getattr(user, 'authenticator_secret', None):
        secret = pyotp.random_base32()
        user.authenticator_secret = secret
        user.save()
    else:
        secret = user.authenticator_secret
    # Generate provisioning URI
    totp = pyotp.TOTP(secret)
    issuer_name = "2FA Project"
    provisioning_uri = totp.provisioning_uri(name=user.email, issuer_name=issuer_name)
    # Generate QR as base64
    qr = qrcode.QRCode(border=2, box_size=8)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    # Convert QR image to base64
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    qr_image_base64 = base64.b64encode(buffer.getvalue()).decode()
    qr_image_url = f"data:image/png;base64,{qr_image_base64}"
    # Render setup authenticator page
    if request.method == 'POST':
        token = request.POST.get('token', '').strip()
        if totp.verify(token):
            user.is_two_factor_enabled = True
            user.save()
            # Clean session and redirect to login
            request.session.pop('setup_user_id', None)

            messages.success(request, "Two-Factor Authentication setup complete! 🎉 You can now login.")
            return redirect('login')
        else:
            messages.error(request, "Invalid authenticator code. Please try again.")
    return render(request, 'core/setup-authenticator.html', {
        'secret_key': secret,
        'qr_image_url': qr_image_url
    })

#login view
@csrf_protect
@require_http_methods(["GET", "POST"])
def login_view(request):
    if request.method == 'GET':
        return render(request, 'core/login.html')
    # Honeypot check
    if request.POST.get("bot_catcher"):
        messages.error(request, "Suspicious activity detected.")
        return redirect("login")
    phone = request.POST.get('phone', '').strip()
    password = request.POST.get('password', '')
    if not phone or not password:
        messages.error(request, "Phone and password are required.")
        return render(request, 'core/login.html')
    # Normalize phone number
    try:
        parsed_number = phonenumbers.parse(phone, "KE")
        if not phonenumbers.is_valid_number(parsed_number):
            raise ValueError()
        formatted_phone = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
    except Exception:
        messages.error(request, "Enter a valid Kenyan phone number.")
        return render(request, 'core/login.html')
    ip = get_client_ip(request)
    # Brute force protection
    recent_attempts = LoginAttempt.objects.filter(
        ip_address=ip,
        timestamp__gte=timezone.now() - timezone.timedelta(minutes=10),
        success=False
    )
    if recent_attempts.count() >= 5:
        messages.error(request, "Too many failed login attempts. Try again later.")
        return render(request, 'core/login.html')
    # Authenticate user
    try:
        user = User.objects.get(phone=formatted_phone)
    except User.DoesNotExist:
        user = None
    if user and user.check_password(password):
        if not user.is_active:
            messages.warning(request, "Your account is inactive. OTP sent to your email.")
            return redirect('send-inactive-otp')
        # Log successful login attempt
        login(request, user)
        LoginAttempt.objects.create(user=user, ip_address=ip, success=True)
        request.session['just_logged_in'] = True
        # Check preferred 2FA method
        method = 'authenticator'  # default fallback
        if hasattr(user, 'profile') and user.profile.preferred_2fa_method:
            method = user.profile.preferred_2fa_method.strip().lower()
        # Redirect based on 2FA method
        if method == 'authenticator':
            return redirect('verify-login-by-authenticator')
        elif method == 'email':
            return redirect('verify-login-by-email')
        else:
            # Unknown method, log and redirect to login
            SecurityLog.objects.create(
                user=user,
                event_type='Login Attempt',
                ip_address=ip,
                user_agent=get_device_info(request),
                details=f"Unknown 2FA method: {method}"
            )
            messages.error(request, "Unknown 2FA method. Contact support.")
            return redirect('login')
        
    else:
        if user:
            # Log failed login attempt
            SecurityLog.objects.create(
                user=user,
                event_type='Login Failed',
                ip_address=ip,
                user_agent=get_device_info(request),
                details='Incorrect phone/password during login.'
            )
            LoginAttempt.objects.create(user=user, ip_address=ip, success=False)
            messages.error(request, "Invalid phone or password.")
            return render(request, 'core/login.html')
        
#auth login verif
MAX_OTP_ATTEMPTS = 5000

#by authenticator
@login_required
def verify_login_by_authenticator_view(request):
    # Check if user just logged in
    if not request.session.get('just_logged_in'):
        messages.error(request, "Access denied. Please login first.")
        return redirect('login')
    # Get user and device info
    user = request.user
    ip = get_client_ip(request)
    device = get_device_info(request)
    attempts_key = f"otp_attempts_{user.id}"
    otp_attempts = request.session.get(attempts_key, 0)
    # http method check
    if request.method == 'POST':
        entered_otp = request.POST.get('otp', '').strip()
        # Block user if maximum attempts reached
        otp_attempts = request.session.get(attempts_key, 0)
        if otp_attempts >= MAX_OTP_ATTEMPTS:
            #throw an error then 
            messages.error(request, "Too many incorrect OTP attempts. Please login again.")
            SecurityLog.objects.create(
                user=user,
                event_type='OTP Blocked',
                ip_address=ip,
                user_agent=device,
                details=f"Exceeded max OTP attempts ({MAX_OTP_ATTEMPTS})"
            )
            request.session.flush()
            return redirect('access-denied')
        # Validate OTP format
        if len(entered_otp) != 6 or not entered_otp.isdigit():
            request.session[attempts_key] = otp_attempts + 1
            messages.error(request, "OTP must be a 6-digit number.")
        else:
            totp_secret = getattr(user, 'authenticator_secret', None)
            if not totp_secret:
                messages.error(request, "2FA not configured properly. Contact support.")
                return redirect('login')
            # Verify OTP using TOTP
            totp = pyotp.TOTP(totp_secret)
            if totp.verify(entered_otp, valid_window=1):
                # Success: clear session and log event
                request.session.pop('just_logged_in', None)
                request.session.pop(attempts_key, None)
                request.session['2fa_verified'] = True
                messages.success(request, "2FA verified successfully.")
                # Log successful verification
                SecurityLog.objects.create(
                    user=user,
                    event_type='OTP Verified',
                    ip_address=ip,
                    user_agent=device,
                    details='Login verified via Google Authenticator.',
                    verified_at=timezone.now()
                )
                # Redirect based on role
                role = getattr(user, 'role', 'user')
                if role == 'admin':
                    return redirect('admin-dashboard')
                elif role == 'security':
                    return redirect('security-dashboard')
                else:
                    return redirect('user-dashboard')
            else:
                messages.error(request, "Invalid OTP.")
                request.session[attempts_key] = otp_attempts + 1
                SecurityLog.objects.create(
                    user=user,
                    event_type='OTP Failed',
                    ip_address=ip,
                    user_agent=device,
                    details='Incorrect OTP during login.'
                )
    else:
        messages.info(request, "Enter the 6-digit code from your Google Authenticator app.")
    return render(request, 'core/verify-login-by-authenticator.html')

#by email
@login_required
def verify_login_by_email_view(request):
    user = request.user
    if not request.session.get('just_logged_in'):
        messages.error(request, "Access denied. Please login first.")
        return redirect('login')
    ip = get_client_ip(request)
    if request.method == 'POST':
        entered_code = request.POST.get('otp', '').strip()

        valid_otp = OTPLog.objects.filter(
            user=user,
            purpose='login',
            code=entered_code,
            sent_via='email',
            expires_at__gte=timezone.now()
        ).order_by('-created_at').first()
        #GOOD otp
        if valid_otp:
            valid_otp.verified = True
            valid_otp.save()
            request.session['2fa_verified'] = True
            messages.success(request, "2FA verified successfully.")
            return redirect('dashboard') 
        else:
            messages.error(request, "Invalid or expired OTP.")
    else:
        # On GET: Generate and send OTP
        otp_code = generate_otp()
        expiry = timezone.now() + timezone.timedelta(minutes=10)
        OTPLog.objects.create(
            user=user,
            code=otp_code,
            purpose='login',
            sent_via='email',
            expires_at=expiry
        )
        try:
            send_otp_via_email(
                [user.email],
                otp_code,
                subject="Login Verification Code",
                body=f"Hi {user.first_name}, your 2FA login code is {otp_code}. It expires in 10 minutes."
            )
        except Exception as e:
            print(f"[ERROR] Email OTP not sent: {e}")
        messages.info(request, "Verification code sent to your email.")
    return render(request, 'core/verify-login-by-email.html')

#Resend otp
@login_required
def resend_otp_view(request):
    user = request.user
    ip = get_client_ip(request)
    device = get_device_info(request)
    if not request.session.get('just_logged_in'):
        messages.error(request, "Access denied. Please login first.")
        return redirect('login')
    messages.info(request, "OTP codes are generated on your Google Authenticator app. Please open the app to get the code.")
    SecurityLog.objects.create(
        user=user,
        event_type='OTP Resend Attempt Denied',
        ip_address=ip,
        user_agent=device,
        details='User requested OTP resend, but 2FA uses Google Authenticator.'
    )
    return redirect('verify-login')

#password reset flow
def select_reset_method_view(request):
    return render(request, 'core/select-reset-method.html')
#select reset method type
def handle_reset_method(request):
    if request.method == 'POST':
        method = request.POST.get('resetOption')
        if method == 'email':
            return redirect('reset-by-email')
        elif method == 'phone':
            return redirect('reset-by-phone')
    return redirect('select-reset-method')
def select_reset_method_view(request):
    return render(request, 'core/select-reset-method.html')

#Reset by email
def reset_by_email_view(request):
    show_otp_form = False
    email_value = ""
    #get email reset password form
    if request.method == 'GET':
        request.session.pop('reset_email', None)
        request.session.pop('reset_email_otp', None)
        return render(request, 'core/reset-by-email.html', {
            'show_otp_form': show_otp_form,
            'email_value': email_value
        })
    action = request.POST.get("action")
    #http method OTP request
    if action == "get_otp":
        email = request.POST.get('email', '').strip()
        email_value = email
        #try get user
        try:    
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, "Email not found.")
            return render(request, 'core/reset-by-email.html', {
                'show_otp_form': False,
                'email_value': email_value
            })
        #log
        now = timezone.now()
        recent_otps = OTPLog.objects.filter(
            user=user,
            purpose='Password Reset',
            sent_via='E-Mail',
            created_at__gte=now - timezone.timedelta(minutes=10)
        ).count()
        #limit otp requests
        if recent_otps >= 3:
            messages.error(request, "Too many OTP requests. Try again later.")
            return render(request, 'core/reset-by-email.html', {
                'show_otp_form': False,
                'email_value': email_value
            })
        #generate otp & create session
        otp = generate_otp()
        request.session['reset_email'] = email
        request.session['reset_email_otp'] = otp
        #send generated otp via email
        try:
            send_otp_via_email(email, otp)
            OTPLog.objects.create(
                user=user,
                code=otp,
                purpose='Password Reset',
                sent_via='E-Mail',
                expires_at=now + timezone.timedelta(minutes=10)
            )
            messages.success(request, f"OTP sent to {email}")
            show_otp_form = True
        #error handling
        except Exception as e:
            messages.error(request, f"Failed to send OTP: {e}")
            request.session.pop('reset_email', None)
            request.session.pop('reset_email_otp', None)
        return render(request, 'core/reset-by-email.html', {
            'show_otp_form': show_otp_form,
            'email_value': email_value
        })
    #create new password & confirm
    elif action == "verify_otp":
        email = request.session.get('reset_email')
        entered_otp = request.POST.get('otp', '').strip()
        new_pass = request.POST.get('password')
        confirm_pass = request.POST.get('confirm_password')
        show_otp_form = True
        if not email:
            messages.error(request, "Session expired. Start again.")
            return redirect('reset-by-email')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, "Invalid session. Start again.")
            return redirect('reset-by-email')
        valid_otp = OTPLog.objects.filter(
            user=user,
            code=entered_otp,
            purpose='Password Reset',
            sent_via='E-Mail',
            expires_at__gte=timezone.now(),
            verified=False
        ).first()
        if not valid_otp:
            OTPLog.objects.create(
                user=user,
                code=entered_otp,
                purpose='Password Reset (Invalid Attempt)',
                sent_via='E-Mail',
                expires_at=timezone.now()
            )
            messages.error(request, "Invalid or expired OTP.")
            return render(request, 'core/reset-by-email.html', {
                'show_otp_form': True,
                'email_value': email
            })
        if new_pass != confirm_pass:
            messages.error(request, "Passwords do not match.")
            return render(request, 'core/reset-by-email.html', {
                'show_otp_form': True,
                'email_value': email
            })
        if len(new_pass) < 8 or not (
            any(c.islower() for c in new_pass) and
            any(c.isupper() for c in new_pass) and
            any(c.isdigit() for c in new_pass) and
            any(c in st.punctuation for c in new_pass)
        ):
            messages.error(request, "Weak password. Must include upper, lower, digit, and symbol.")
            return render(request, 'core/reset-by-email.html', {
                'show_otp_form': True,
                'email_value': email
            })
        #update password
        user.set_password(new_pass)
        user.save()
        #mark OTP as verified
        valid_otp.verified = True
        valid_otp.verified_at = timezone.now()
        valid_otp.save()
        #clear session
        request.session.pop('reset_email', None)
        request.session.pop('reset_email_otp', None)
        messages.success(request, "Password reset successfully. You may now login.")
        return redirect('login')
    messages.error(request, "Invalid form submission.")
    return redirect('reset-by-email')

#verify reset by email
def verify_reset_email_otp_view(request):
    #get pending session with reset by email
    if request.method == 'GET':
        request.session.pop('reset_email', None)
        request.session.pop('reset_email_otp', None)
        return render(request, 'core/verify-reset-email.html')
    #get otp & passwords
    entered_otp = request.POST.get('otp', '').strip()
    new_password = request.POST.get('password')
    confirm_password = request.POST.get('confirm_password')
    email = request.session.get('reset_email')
    if not email:
        messages.error(request, "Session expired. Please restart the process.")
        return redirect('reset-by-email')
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        messages.error(request, "Invalid session or user. Please try again.")
        return redirect('reset-by-email')
    valid_otp = OTPLog.objects.filter(
        user=user,
        code=entered_otp,
        purpose='Password Reset',
        sent_via='E-Mail',
        expires_at__gte=timezone.now(),
        verified=False
    ).first()
    #wrong otp
    if not valid_otp:
        OTPLog.objects.create(
            user=user,
            code=entered_otp,
            purpose='Password Reset (Invalid Attempt)',
            sent_via='E-Mail',
            expires_at=timezone.now()
        )
        messages.error(request, "Invalid or expired OTP.")
        return redirect('verify-reset-email')

    if new_password != confirm_password:
        messages.error(request, "Passwords do not match.")
        return redirect('verify-reset-email')

    if len(new_password) < 8 or not (
        any(c.islower() for c in new_password) and
        any(c.isupper() for c in new_password) and
        any(c.isdigit() for c in new_password) and
        any(c in st.punctuation for c in new_password)
    ):
        messages.error(request, "Weak password. Use upper, lower, digit, and symbol.")
        return redirect('verify-reset-email')

    user.set_password(new_password)
    user.save()

    valid_otp.verified = True
    valid_otp.verified_at = timezone.now()
    valid_otp.save()

    request.session.pop('reset_email', None)
    request.session.pop('reset_email_otp', None)

    messages.success(request, "Password updated. You may now login.")
    return redirect('login')

#reset by authenticator
def reset_by_authenticator_view(request):
    show_otp_form = False
    email_value = ''
    if request.method == 'POST':
        action = request.POST.get('action')
        #get email for authentivation
        if action == 'get_auth_challenge':
            email = request.POST.get('email', '').strip()
            email_value = email
            #get user/check if in db
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                messages.error(request, "No user found with that email.")
                return render(request, 'core/reset-by-authenticator.html', {
                    'show_otp_form': False,
                    'email_value': email
                })
            #check profile for secret TOTP
            if not hasattr(user, 'profile') or not user.profile.totp_secret:
                messages.error(request, "Authenticator not configured for this account.")
                return render(request, 'core/reset-by-authenticator.html', {
                    'show_otp_form': False,
                    'email_value': email
                })
            request.session['reset_user_id'] = user.id
            show_otp_form = True
            return render(request, 'core/reset-by-authenticator.html', {
                'show_otp_form': show_otp_form,
                'email_value': email
            })
        elif action == 'verify_auth_code':
            user_id = request.session.get('reset_user_id')
            if not user_id:
                messages.error(request, "Session expired. Please start again.")
                return redirect('reset-by-authenticator')
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                messages.error(request, "User not found.")
                return redirect('reset-by-authenticator')
            email_value = user.email
            #show otp, pass & confirm pass page
            show_otp_form = True
            #get otp, pass & confirm
            auth_code = request.POST.get('auth_code', '').strip()
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')
            totp_secret = getattr(user.profile, 'totp_secret', None)
            #errors handling
            if not totp_secret:
                messages.error(request, "Authenticator not configured for this account.")
                return render(request, 'core/reset-by-authenticator.html', {
                    'show_otp_form': True,
                    'email_value': email_value
                })
            #Auth code validation
            totp = pyotp.TOTP(totp_secret)
            if not totp.verify(auth_code, valid_window=1):
                messages.error(request, "Invalid authenticator code.")
                SecurityLog.objects.create(
                    user=user,
                    event_type='Password Reset TOTP Failed',
                    ip_address=get_client_ip(request),
                    user_agent=get_device_info(request),
                    details='Incorrect authenticator code during password reset.'
                )
                return render(request, 'core/reset-by-authenticator.html', {
                    'show_otp_form': True,
                    'email_value': email_value
                })

            if password != confirm_password:
                messages.error(request, "Passwords do not match.")
                return render(request, 'core/reset-by-authenticator.html', {
                    'show_otp_form': True,
                    'email_value': email_value
                })

            if len(password) < 8 or not (
                any(c.islower() for c in password) and
                any(c.isupper() for c in password) and
                any(c.isdigit() for c in password) and
                any(c in st.punctuation for c in password)
            ):
                messages.error(request, "Weak password. Use uppercase, lowercase, digits, and symbols.")
                return render(request, 'core/reset-by-authenticator.html', {
                    'show_otp_form': True,
                    'email_value': email_value
                })

            user.password = make_password(password)
            user.save()

            SecurityLog.objects.create(
                user=user,
                event_type='Password Reset Success',
                ip_address=get_client_ip(request),
                user_agent=get_device_info(request),
                details='Password successfully reset via authenticator.'
            )

            request.session.pop('reset_user_id', None)
            messages.success(request, "Password updated successfully. You may now login.")
            return redirect('login')

    else:
        request.session.pop('reset_user_id', None)

    return render(request, 'core/reset-by-authenticator.html', {
        'show_otp_form': show_otp_form,
        'email_value': email_value
    })



#logout
from django.contrib.sessions.models import Session
@require_POST
@csrf_protect
def logout_view(request):
    if request.user.is_authenticated:
        # Log the logout event
        SecurityLog.objects.create(
            user=request.user,
            event_type='Logout',
            ip_address=get_client_ip(request),
            user_agent=get_device_info(request),
            details='User logged out.'
        )

        # Kill all active sessions for the user
        sessions = Session.objects.filter(expire_date__gte=timezone.now())
        for session in sessions:
            data = session.get_decoded()
            if data.get('_auth_user_id') == str(request.user.id):
                session.delete()

        logout(request)

    return redirect('login')



#Logs API route

@login_required
def get_logs_api(request):
    user = request.user
    
    logs_qs = SecurityLog.objects.filter(user=user).order_by('-created_at')[:10]
   
    logs = [
        f"{log.event_type} on {log.created_at.strftime('%Y-%m-%d %H:%M:%S')} — {log.details}"
        for log in logs_qs
    ]
    return JsonResponse({"logs": logs})

#Roles

def dashboard_view(request):
    role = getattr(request.user, 'role', 'user')
    if role == 'admin':
        return redirect('admin-dashboard')
    elif role == 'security':
        return redirect('security-dashboard')
    return redirect('user-dashboard')


#User dashbard

@login_required
def user_dashboard(request):
    user = request.user
    start_time = user.date_joined

    otp_logs = OTPLog.objects.filter(user=user, created_at__gte=start_time).order_by('-created_at')[:50000]
    login_attempts = LoginAttempt.objects.filter(user=user, timestamp__gte=start_time).order_by('-timestamp')[:50000]
    security_logs = SecurityLog.objects.filter(user=user, timestamp__gte=start_time).order_by('-timestamp')[:50000]
    logs = []
    # logs
    for log in otp_logs:
        logs.append({
            'type': 'OTP',
            'datetime': log.created_at,
            'details': f"Code: {log.code}, Purpose: {log.purpose}, Via: {log.sent_via}, Verified: {'Yes' if log.verified else 'No'}",
            'contact': user.email if user.email else user.phone
        })

    # login attempts
    for attempt in login_attempts:
        status = "Success" if attempt.success else "Failed"
        logs.append({
            'type': 'Login',
            'datetime': attempt.timestamp,
            'details': f"{status} from IP {attempt.ip_address}",
            'contact': user.email if user.email else user.phone
        })

    #security logs
    for sec_log in security_logs:
        logs.append({
            'type': 'Security',
            'datetime': sec_log.timestamp,
            'details': f"Event: {sec_log.event_type}, Details: {sec_log.details or 'N/A'}, IP: {sec_log.ip_address}",
            'contact': user.email if user.email else user.phone
        })
        

    # Sort by datetime descending
    logs.sort(key=lambda x: x['datetime'], reverse=True)

    return render(request, 'core/user-dashboard.html', {'logs': logs})




#in profile change password
@login_required
def change_password_view(request):
    if request.method == 'POST':
        form = PasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Prevent logout
            messages.success(request, "Password updated successfully.")
            return redirect('dashboard')
    else:
        form = PasswordChangeForm(user=request.user)
    return render(request, 'core/change-password.html', {'form': form})

@login_required
def update_password_view(request):
    if request.method == 'POST':
        form = CustomPasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, "Password updated successfully.")
            return redirect('dashboard')
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = CustomPasswordChangeForm(user=request.user)

    return render(request, 'core/user-dashboard.html', {
        'form': form,
        'section': 'settings'
    })


# in profile update 2fa metod
@login_required
@require_POST
def update_2fa_method_view(request):
    method = request.POST.get('method', '').strip().lower()
    valid_methods = ['email', 'authenticator']
    
    if method not in valid_methods:
        messages.error(request, "Invalid 2FA method selected.")
        return redirect('dashboard')
    
    profile, _ = Profile.objects.get_or_create(user=request.user)
    profile.preferred_2fa_method = method
    profile.save()

    SecurityLog.objects.create(
        user=request.user,
        event_type='2FA Method Changed',
        ip_address=get_client_ip(request),
        user_agent=get_device_info(request),
        details=f"2FA method successfully changed to '{method}'"
    )

    messages.success(request, f"Your 2FA method was updated to '{method.capitalize()}'.")
    return redirect('dashboard')

#in profile Update notification
@login_required
def update_notifications_view(request):
    if request.method == 'POST':
        profile, _ = Profile.objects.get_or_create(user=request.user)
        profile.login_alerts = bool(request.POST.get('login_alerts'))
        profile.email_alerts = bool(request.POST.get('email_alerts'))
        profile.save()

        messages.success(request, "Notification preferences updated.")
    return redirect('dashboard')


#Admin dashboard
@user_passes_test(lambda u: u.role == 'admin')
def admin_dashboard_view(request):
    section = request.GET.get('section', 'users')
    context = {'section': section}

    if request.method == 'POST' and section == 'otp':
        method = request.POST.get('default_method', 'whatsapp').lower()
        expiry = request.POST.get('expiry_minutes', '5')

        otp_settings, _ = OTPSetting.objects.get_or_create(id=1)
        otp_settings.default_method = method if method in ['email', 'authenticator'] else 'email'

        try:
            otp_settings.expiry_minutes = max(1, int(expiry))
        except (ValueError, TypeError):
            otp_settings.expiry_minutes = 5 

        otp_settings.save()
        messages.success(request, "OTP settings updated successfully.")
        context['otp_settings'] = otp_settings
    

    if section == 'users':
        context['users'] = CustomUser.objects.all()
    elif section == 'logs':
        context['logs'] = SecurityLog.objects.all().order_by('-timestamp')
    elif section == 'otp':
        context['otp_settings'] = OTPSetting.objects.first()

    return render(request, 'core/admin_dashboard.html', context)


#Admin level roles elevation
@user_passes_test(lambda u: u.role == 'admin')
def admin_elevate_roles_view(request):
    if request.method == 'POST':
        user_id = request.POST.get('update_user')
        if not user_id:
            messages.error(request, "No user selected for update.")
            return redirect('admin-dashboard')

        user = get_object_or_404(CustomUser, id=user_id)
        new_role = request.POST.get(f'role_{user_id}', '').lower()

        if new_role in ['user', 'security', 'admin']:
            user.role = new_role
            user.save()
            messages.success(request, f"User {user.phone} role updated to {new_role}.")
        else:
            messages.error(request, "Invalid role selected.")

    return redirect('admin-dashboard')
#access denied
@login_required
def access_denied_view(request):
    messages.error(request, "You do not have permission to access this page.")
    return render(request, 'core/access-denied.html')
#security dashboard
from collections import Counter
@login_required
def security_dashboard_view(request):
    if request.user.role != 'security':
        messages.error(request, "Access restricted to security personnel only.")
        return redirect('access-denied')

    seven_days_ago = now() - timedelta(days=700)
    logs_qs = SecurityLog.objects.select_related('user').filter(
        user__role__in=['user', 'security'],
        timestamp__gte=seven_days_ago
    ).order_by('-timestamp')

    # Count failed login attempts from event_type
    failed_attempts = logs_qs.filter(event_type='failed_login').count()

    # Peak usage hour (based on any log timestamps)
    hour_counter = Counter(log.timestamp.hour for log in logs_qs)
    peak_hour = hour_counter.most_common(1)[0][0] if hour_counter else None

    # Unusual login — we assume the first login in time is the unusual one
    unusual_login = logs_qs.filter(event_type='login').order_by('timestamp').first()
    unusual_login_date = unusual_login.timestamp.date() if unusual_login else None

    context = {
        'logs': logs_qs[:100],
        'peak_hour': peak_hour,
        'unusual_login_date': unusual_login_date,
        'failed_attempts': failed_attempts
    }

    return render(request, 'core/security-dashboard.html', context)

#error
def error_view(request):
    return render(request, 'core/error.html')


def success_view(request):
    return render(request, 'core/success.html')


#notifications
@login_required
def update_notifications_view(request):
    if request.method == 'POST':
        profile, _ = Profile.objects.get_or_create(user=request.user)
        profile.login_alerts = bool(request.POST.get('login_alerts'))
        profile.email_alerts = bool(request.POST.get('email_alerts'))
        profile.save()
        messages.success(request, "Notification preferences updated.")
    return redirect('user-dashboard')

#user login handler
@receiver(user_logged_in)
def handle_user_login(sender, request, user, **kwargs):
    profile = getattr(user, 'profile', None)
    if not profile:
        return 

    ip = get_client_ip(request)

    if profile.email_alerts and user.email:
        try:
            send_mail(
                subject="Login Alert",
                message=f"Your account was accessed from IP address: {ip}.",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=True,
            )
        except Exception as e:
            print(f"[LOGIN ALERT] Email failed: {e}")

    if profile.login_alerts:
        request.session['login_alert_message'] = f"Login detected from IP {ip}"

def is_admin_or_security(user):
    return user.is_authenticated and user.role in ['admin', 'security']


#action against users
@login_required
@user_passes_test(is_admin_or_security)
def block_user_view(request, user_id):
    if request.method == 'POST':
        user_to_block = get_object_or_404(User, id=user_id)
        if user_to_block.is_active:
            user_to_block.is_active = False
            user_to_block.save()
            messages.success(request, f"User {user_to_block.get_full_name()} has been blocked.")
        else:
            messages.warning(request, "User is already blocked.")
    return redirect(request.META.get('HTTP_REFERER', '/'))

 
@login_required
@user_passes_test(is_admin_or_security)
def unblock_user_view(request, user_id):
    if request.method == 'POST':
        user_to_unblock = get_object_or_404(User, id=user_id)
        if not user_to_unblock.is_active:
            user_to_unblock.is_active = True
            user_to_unblock.save()
            messages.success(request, f"User {user_to_unblock.get_full_name()} has been unblocked.")
        else:
            messages.warning(request, "User is already active.")

        logs = SecurityLog.objects.select_related('user').order_by('-timestamp')[:100] 
    return render(request, 'core/admin-dashboard.html', {
        'logs': logs,
        'section': request.GET.get('section', '')  
    })
    return redirect(request.META.get('HTTP_REFERER', '/'))

#admin
@login_required
def admin_dashboard(request):
    if not request.user.is_superuser:
        messages.error(request, "Access denied.")
        return redirect('access-denied')
    if request.user.role != 'admin':
        messages.error(request, "Access restricted to security personnel only.")
        return redirect('core/access-denied.html')

    section = request.GET.get('section', 'users')
    selected_user = None
    otp_logs = None

    if section == 'manage-otps':
        user_id = request.GET.get('user_id')
        if user_id:
            selected_user = CustomUser.objects.filter(id=user_id).first()
            if selected_user:
                otp_logs = OTPLog.objects.filter(user=selected_user).order_by('-created_at')

    context = {
        'section': section,
        'all_users': CustomUser.objects.all(),
        'selected_user': selected_user,
        'otp_logs': otp_logs,
        'users': CustomUser.objects.all(),
        'logs': SecurityLog.objects.order_by('-timestamp')[:100],
        'otp_settings': OTPSetting.objects.first(),
    }
    return render(request, 'core/admin_dashboard.html', context)

#profile update
@login_required
def update_profile(request):
    if request.method == 'POST':
        user = request.user
        user.first_name = request.POST.get('first_name', user.first_name)
        user.last_name = request.POST.get('last_name', user.last_name)
        user.email = request.POST.get('email', user.email)
        user.phone = request.POST.get('phone', user.phone)
        user.save()
        messages.success(request, "Profile updated successfully.")
    return redirect('user-dashboard')


#manage otps
@login_required
def manage_otp_settings(request):
    if not request.user.is_superuser:
        messages.error(request, "Access denied.")
        return redirect('dashboard')

    otp_settings, _ = OTPSetting.objects.get_or_create(id=1)

    if request.method == 'POST':
        method = request.POST.get('default_method', 'whatsapp')
        expiry = request.POST.get('expiry_minutes', '5')

        try:
            otp_settings.default_method = method
            otp_settings.expiry_minutes = int(expiry)
            otp_settings.save()
            messages.success(request, "Settings updated successfully.")
        except ValueError:
            messages.error(request, "Invalid expiry value.")

        return redirect(f"{request.path}?section=otp")

    return render(request, 'core/admin_dashboard.html', {
        'otp_settings': otp_settings,
        'section': 'otp'
    })
