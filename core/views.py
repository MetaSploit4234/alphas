# Django core imports
from django import forms
from datetime import timedelta
from django.conf import settings
from django.contrib import messages
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
    
    #detected acts
    if request.POST.get("bot_catcher"):
        messages.error(request, "Suspicious activity detected.")
        return redirect("register")
    
    #ip
    ip = get_client_ip(request)

    #log recent attempts
    recent_attempts = SecurityLog.objects.filter(
        ip_address=ip,
        event_type="Registration",
        timestamp__gte=timezone.now() - timezone.timedelta(minutes=5)
    ).count()

    #check recent atteempts
    if recent_attempts >= 3:
        messages.error(request, "Too many signup attempts. Please wait a few minutes.")
        return render(request, 'core/access-denied.html')
    
    #get user info
    first_name = request.POST.get("first_name", "").strip()
    last_name = request.POST.get("last_name", "").strip()
    email = request.POST.get("email", "").strip()
    phone = request.POST.get("phone", "").strip()
    password = request.POST.get("password", "")
    confirm_password = request.POST.get("confirm_password", "")

    #validate user info
    if not all([first_name, last_name, email, phone, password, confirm_password]):
        messages.error(request, "All fields are required.")
        return render(request, 'core/register.html')
    if User.objects.filter(phone=phone).exists():
        messages.error(request, "Phone number already exists.")
        return render(request, 'core/register.html') 
    if User.objects.filter(email=email).exists():
        messages.error(request, "Email already registered.")
        return render(request, 'core/register.html')
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
    #Model injection
    try:
        with transaction.atomic():
            # Create default inactive user
            user = User.objects.create_user(
                phone=formatted_phone,
                first_name=first_name,
                last_name=last_name,
                email=email,
                password=password,
                is_active=False
            )

            logger.info(f"User created with ID {user.id}")

            # Generate TOTP secret and save in Profile
            totp_secret = pyotp.random_base32()
            profile, created = Profile.objects.get_or_create(user=user)
            profile.totp_secret = totp_secret
            profile.save()
            logger.info(f"Profile {'created' if created else 'updated'} for user ID {user.id}")

            # Generate email OTP for signup verification
            email_otp = generate_otp()
            print(f"Email otp is: {email_otp}")
            expiry = timezone.now() + timezone.timedelta(minutes=10)

            #logs
            OTPLog.objects.create(
                user=user,
                code=email_otp,
                purpose='signup',
                sent_via='email',
                expires_at=expiry
            )

            logger.info(f"OTPLog created with code {email_otp} for user ID {user.id}")

            # Log the registration event
            SecurityLog.objects.create(
                user=user,
                event_type="Registration",
                ip_address=ip,
                user_agent=get_device_info(request),
                details="New user registered with Google Authenticator TOTP."
            )
            logger.info(f"SecurityLog entry created for user ID {user.id}")

            # Store user info in session for verification step
            request.session['pending_user'] = formatted_phone
            request.session['pending_signup'] = True

            # Generate provisioning URI and QR code SVG for Google Authenticator setup
            totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
                name=user.email,
                issuer_name="YourAppName"
            )

            factory = qrcode.image.svg.SvgImage
            img = qrcode.make(totp_uri, image_factory=factory)
            buffer = BytesIO()
            img.save(buffer)
            svg_data = buffer.getvalue().decode()
            request.session['totp_qr_svg'] = svg_data
            logger.info("QR code SVG generated and saved in session")

            # Send OTP to email
            send_signup_email_otp(user, email_otp)
            logger.info("Signup OTP email sent")

    except IntegrityError as e:
        logger.error(f"IntegrityError during registration: {e}")
        messages.error(request, "Registration failed due to server error.")
        return render(request, 'core/register.html')

    except Exception as e:
        logger.error(f"Unexpected error during registration: {e}", exc_info=True)
        messages.error(request, "Registration failed due to server error.")
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


#Login
@csrf_protect
@require_http_methods(["GET", "POST"])
def login_view(request):
    if request.method == 'POST':
        #get user input plus relevant metadata
        phone_input = request.POST.get("phone", "").strip()
        password = request.POST.get("password", "")
        ip = get_client_ip(request)
        device = get_device_info(request)
        recent_ip_attempts = LoginAttempt.objects.filter(
            ip_address=ip,
            timestamp__gte=timezone.now() - timedelta(minutes=10)
        )
        # Check for brute force attempts from IP
        failed_ip_attempts = recent_ip_attempts.filter(success=False).count()
        if failed_ip_attempts >= 5:
            messages.error(request, "Too many attempts from this IP. Try again later.")
            SecurityLog.objects.create(
                user=None,
                event_type="IP Brute Force Block",
                ip_address=ip,
                user_agent=device,
                details="Blocked after 5+ failed attempts from same IP"
            )
            return render(request, 'core/access-denied.html')
        # Validate phone number format using module
        try:
            parsed = phonenumbers.parse(phone_input, "KE")
            if not phonenumbers.is_valid_number(parsed):
                raise ValueError()
            formatted_phone = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        except Exception:
            messages.error(request, "Please enter a valid Kenyan phone number.")
            return render(request, 'core/login.html')
        recent_user_attempts = LoginAttempt.objects.filter(
            user__phone=formatted_phone,
            timestamp__gte=timezone.now() - timedelta(minutes=10)
        )
        # Check for brute force attempts from user
        failed_user_attempts = recent_user_attempts.filter(success=False).count()
        if failed_user_attempts >= 5:
            messages.error(request, "Too many failed attempts. Try again later.")
            SecurityLog.objects.create(
                user=None,
                event_type="User Brute Force Block",
                ip_address=ip,
                user_agent=device,
                details=f"Blocked after 5+ failed attempts for {formatted_phone}"
            )
            return render(request, 'core/access-denied.html')
        try:
            user = User.objects.get(phone=formatted_phone)
        except User.DoesNotExist:
            user = None

        if user and user.check_password(password):
            if not user.is_active:
                # Generate and send email OTP only (Google Authenticator secret already set)
                email_otp = generate_otp()
                expiry = timezone.now() + timezone.timedelta(minutes=10)

                OTPLog.objects.create(
                    user=user,
                    code=email_otp,
                    purpose='signup',
                    sent_via='email',
                    expires_at=expiry
                )

                request.session['pending_signup'] = True
                request.session['pending_user'] = user.phone

                try:
                    send_otp_via_email(
                        [user.email],
                        email_otp,
                        subject="Signup OTP",
                        body=f"Hello {user.first_name}, your signup OTP is {email_otp}. It expires in 10 minutes."
                    )
                except Exception as e:
                    print(f"Failed to send email OTP during login resend: {e}")

                messages.warning(request, "Your account isn't activated yet. We resent the verification code to your email. Please verify.")
                return redirect('verify-signup')

            # Active user: proceed to login and 2FA verification
            login(request, user)
            request.session['just_logged_in'] = True

            SecurityLog.objects.create(
                user=user,
                event_type='Login Success',
                ip_address=ip,
                user_agent=device,
                details='User logged in successfully.'
            )

            LoginAttempt.objects.create(
                user=user,
                ip_address=ip,
                device_info=device,
                success=True
            )

            return redirect('verify-login')

        else:
            # Invalid credentials
            LoginAttempt.objects.create(
                user=user if user else None,
                ip_address=ip,
                device_info=device,
                success=False
            )
            SecurityLog.objects.create(
                user=None,
                event_type='Login Failed',
                ip_address=ip,
                user_agent=device,
                details=f'Login failed for {formatted_phone}'
            )
            messages.error(request, "Invalid phone number or password.")

    return render(request, 'core/login.html')


MAX_OTP_ATTEMPTS = 5

@login_required
def verify_login_view(request):
    if not request.session.get('just_logged_in'):
        messages.error(request, "Access denied. Please login first.")
        return redirect('login')
    user = request.user
    ip = get_client_ip(request)
    device = get_device_info(request)
    attempts_key = f"otp_attempts_{user.id}"
    if request.method == 'POST':
        entered_otp = request.POST.get('otp', '').strip()
        otp_attempts = request.session.get(attempts_key, 0)
        if otp_attempts >= MAX_OTP_ATTEMPTS:
            messages.error(request, "Too many incorrect OTP attempts. Please login again.")
            SecurityLog.objects.create(
                user=user,
                event_type='OTP Blocked',
                ip_address=ip,
                user_agent=device,
                details=f"Exceeded max OTP attempts ({MAX_OTP_ATTEMPTS})"
            )
            request.session.flush()
            return redirect('login')
        if len(entered_otp) != 6 or not entered_otp.isdigit():
            request.session[attempts_key] = otp_attempts + 1
        else:
            totp_secret = getattr(user, 'authenticator_secret', None)
            if not totp_secret:
                messages.error(request, "2FA not configured properly. Contact support.")
                return redirect('login')
            totp = pyotp.TOTP(totp_secret)
            if totp.verify(entered_otp, valid_window=1):
                request.session.pop('just_logged_in', None)
                request.session.pop(attempts_key, None)
                SecurityLog.objects.create(
                    user=user,
                    event_type='OTP Verified',
                    ip_address=ip,
                    user_agent=device,
                    details='Login verified via Google Authenticator.',
                    verified_at=timezone.now()
                )
                role = getattr(user, 'role', 'user')
                if role == 'admin':
                    return redirect('admin-dashboard')
                elif role == 'security':
                    return redirect('security-dashboard')
                else:
                    return redirect('user-dashboard')
            else:
                messages.error(request, "Invalid OTP.")
                SecurityLog.objects.create(
                    user=user,
                    event_type='OTP Failed',
                    ip_address=ip,
                    user_agent=device,
                    details='Incorrect OTP during login.'
                )
                request.session[attempts_key] = otp_attempts + 1

    else:
        messages.info(request, "Enter the 6-digit code from your Google Authenticator app.")

    return render(request, 'core/verify-login.html')



#Resend otp
@login_required
def resend_otp_view(request):
    user = request.user
    ip = get_client_ip(request)
    device = get_device_info(request)

    if not request.session.get('just_logged_in'):
        messages.error(request, "Access denied. Please login first.")
        return redirect('login')

    # With Google Authenticator, no OTP sending is done by server
    # So simply deny resend requests or provide info

    messages.info(request, "OTP codes are generated on your Google Authenticator app. Please open the app to get the code.")

    SecurityLog.objects.create(
        user=user,
        event_type='OTP Resend Attempt Denied',
        ip_address=ip,
        user_agent=device,
        details='User requested OTP resend, but 2FA uses Google Authenticator.'
    )

    return redirect('verify-login')

def select_reset_method_view(request):
    return render(request, 'core/select-reset-method.html')


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



def handle_reset_method(request):
    if request.method == 'POST':
        option = request.POST.get('resetOption')
        if option == 'authenticator':
            return redirect('reset-by-authenticator')
        elif option == 'email':
            return redirect('reset-by-email')
    # fallback if method is not POST or invalid option
    return redirect('select-reset-method')


#Reset by email

def reset_by_email_view(request):
    show_otp_form = False
    email_value = ""

    if request.method == 'GET':
        request.session.pop('reset_email', None)
        request.session.pop('reset_email_otp', None)
        return render(request, 'core/reset-by-email.html', {
            'show_otp_form': show_otp_form,
            'email_value': email_value
        })

    action = request.POST.get("action")

    if action == "get_otp":
        email = request.POST.get('email', '').strip()
        email_value = email

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, "Email not found.")
            return render(request, 'core/reset-by-email.html', {
                'show_otp_form': False,
                'email_value': email_value
            })

        now = timezone.now()
        recent_otps = OTPLog.objects.filter(
            user=user,
            purpose='Password Reset',
            sent_via='E-Mail',
            created_at__gte=now - timezone.timedelta(minutes=10)
        ).count()

        if recent_otps >= 3:
            messages.error(request, "Too many OTP requests. Try again later.")
            return render(request, 'core/reset-by-email.html', {
                'show_otp_form': False,
                'email_value': email_value
            })

        otp = generate_otp()
        request.session['reset_email'] = email
        request.session['reset_email_otp'] = otp

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

        except Exception as e:
            messages.error(request, f"Failed to send OTP: {e}")
            request.session.pop('reset_email', None)
            request.session.pop('reset_email_otp', None)

        return render(request, 'core/reset-by-email.html', {
            'show_otp_form': show_otp_form,
            'email_value': email_value
        })

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

        user.set_password(new_pass)
        user.save()

        valid_otp.verified = True
        valid_otp.verified_at = timezone.now()
        valid_otp.save()

        request.session.pop('reset_email', None)
        request.session.pop('reset_email_otp', None)

        messages.success(request, "Password reset successfully. You may now login.")
        return redirect('login')
    
    messages.error(request, "Invalid form submission.")
    return redirect('reset-by-email')


#verify reset by email

def verify_reset_email_otp_view(request):
    if request.method == 'GET':
        request.session.pop('reset_email', None)
        request.session.pop('reset_email_otp', None)
        return render(request, 'core/verify-reset-email.html')

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
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
import pyotp
import string as st
from .models import SecurityLog
from .utils import get_client_ip, get_device_info

User = get_user_model()

def reset_by_authenticator_view(request):
    show_password_fields = False

    if request.method == 'POST':
        action = request.POST.get('action')
        user_id = request.session.get('reset_user_id')

        # Step 1: verify authenticator code
        if action == 'verify_totp':
            entered_totp = request.POST.get('totp_code', '').strip()

            if not user_id:
                messages.error(request, "Session expired. Please start again.")
                return redirect('reset-by-authenticator')

            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                messages.error(request, "User not found.")
                return redirect('reset-by-authenticator')

            totp_secret = getattr(user.profile, 'totp_secret', None)
            if not totp_secret:
                messages.error(request, "Authenticator not configured for this account.")
                return redirect('reset-by-authenticator')

            totp = pyotp.TOTP(totp_secret)
            if not totp.verify(entered_totp, valid_window=1):
                messages.error(request, "Invalid authenticator code.")

                # log failed attempt
                SecurityLog.objects.create(
                    user=user,
                    event_type='Password Reset TOTP Failed',
                    ip_address=get_client_ip(request),
                    user_agent=get_device_info(request),
                    details='Incorrect authenticator code during password reset.'
                )
                return render(request, 'core/reset-by-authenticator.html', {
                    'show_password_fields': False
                })

            # Verified → set session flag
            request.session['totp_verified'] = True

            SecurityLog.objects.create(
                user=user,
                event_type='Password Reset TOTP Success',
                ip_address=get_client_ip(request),
                user_agent=get_device_info(request),
                details='Authenticator code verified during password reset.'
            )

            show_password_fields = True
            return render(request, 'core/reset-by-authenticator.html', {
                'show_password_fields': show_password_fields
            })

        # Step 2: update password
        elif action == 'update_password':
            if not user_id or not request.session.get('totp_verified'):
                messages.error(request, "Invalid session. Please start again.")
                return redirect('reset-by-authenticator')

            new_password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')

            # validate match
            if new_password != confirm_password:
                messages.error(request, "Passwords do not match.")
                return render(request, 'core/reset-by-authenticator.html', {
                    'show_password_fields': True
                })

            # validate strength
            if len(new_password) < 8 or not (
                any(c.islower() for c in new_password) and
                any(c.isupper() for c in new_password) and
                any(c.isdigit() for c in new_password) and
                any(c in st.punctuation for c in new_password)
            ):
                messages.error(request, "Weak password. Use uppercase, lowercase, digits, and symbols.")
                return render(request, 'core/reset-by-authenticator.html', {
                    'show_password_fields': True
                })

            try:
                user = User.objects.get(id=user_id)
                user.password = make_password(new_password)
                user.save()

                SecurityLog.objects.create(
                    user=user,
                    event_type='Password Reset Success',
                    ip_address=get_client_ip(request),
                    user_agent=get_device_info(request),
                    details='Password successfully reset via authenticator.'
                )

                # cleanup
                request.session.pop('reset_user_id', None)
                request.session.pop('totp_verified', None)

                messages.success(request, "Password updated successfully. You may now login.")
                return redirect('login')
            except User.DoesNotExist:
                messages.error(request, "User not found.")
                return redirect('reset-by-authenticator')

    else:
        # GET → start: ask for authenticator code
        # you need to know which user is resetting (e.g., store in session before)
        # for demo, just set fake user_id in session:
        # request.session['reset_user_id'] = user.id
        request.session.pop('totp_verified', None)

    return render(request, 'core/reset-by-authenticator.html', {
        'show_password_fields': show_password_fields
    })



#logout

@require_POST
@csrf_protect
def logout_view(request):
    if request.user.is_authenticated:
        SecurityLog.objects.create(
            user=request.user,
            event_type='Logout',
            ip_address=get_client_ip(request),
            user_agent=get_device_info(request),
            details='User logged out.'
        )
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
def update_2fa_method_view(request):
    if request.method == 'POST':
        method = request.POST.get('method', '').lower()
        SecurityLog.objects.create(
            user=request.user,
            event_type='2FA Method Change',
            ip_address=get_client_ip(request),
            user_agent=get_device_info(request),
            details=f"User changed 2FA method to {method}"
        )

        if method not in ['email', 'whatsapp']:
            messages.error(request, "Invalid 2FA method selected.")
            SecurityLog.objects.create(
                user=request.user,
                event_type='2FA Method failed to Change',
                ip_address=get_client_ip(request),
                user_agent=get_device_info(request),
                details="Method update failed"
            )

            return redirect('dashboard')

        profile, _ = Profile.objects.get_or_create(user=request.user)
        profile.two_fa_method = method
        profile.save()

        messages.success(request, f"2FA method updated to {method.capitalize()}.")
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
#security dashboard
@login_required
def security_dashboard_view(request):
    if getattr(request.user, 'role', None) != 'security':
        messages.error(request, "Access restricted.")
        return redirect('access-denied')

    logs = SecurityLog.objects.filter(user__role__in=['user', 'security']).order_by('-timestamp')[:50]
    return render(request, 'core/security-dashboard.html', {'logs': logs})


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
