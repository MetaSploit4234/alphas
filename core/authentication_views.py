from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, get_user_model
from django.utils import timezone
from django.db import IntegrityError, transaction
from django.contrib.auth.decorators import login_required

from email_validator import validate_email as email_validate, EmailNotValidError
from datetime import timedelta
import phonenumbers, threading, string as st

from core.models import OTPLog, LoginAttempt, SecurityLog
from core.utils import generate_otp, send_otp_via_email, send_otp_via_whatsapp

User = get_user_model()


def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    return x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get("REMOTE_ADDR")

def get_device_info(request):
    return request.META.get("HTTP_USER_AGENT", "Unknown Device")


def register_view(request):
    if request.method != 'POST':
        return render(request, 'core/register.html')

    first_name = request.POST.get("first_name", "").strip()
    last_name = request.POST.get("last_name", "").strip()
    email = request.POST.get("email", "").strip()
    phone = request.POST.get("phone", "").strip()
    password = request.POST.get("password", "")
    confirm_password = request.POST.get("confirm_password", "")

    if not all([first_name, last_name, email, phone, password, confirm_password]):
        messages.error(request, "All fields are required.")
        return render(request, 'core/register.html')

    if User.objects.filter(phone=phone).exists():
        messages.error(request, "Phone number already exists!")
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

    if not (any(c.islower() for c in password) and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password) and any(c in st.punctuation for c in password)):
        messages.error(request, "Weak password. Must include uppercase, lowercase, digit, and symbol.")
        return render(request, 'core/register.html')

    if password != confirm_password:
        messages.error(request, "Passwords do not match.")
        return render(request, 'core/register.html')

    try:
        with transaction.atomic():
            user = User.objects.create_user(
                phone=formatted_phone,
                first_name=first_name,
                last_name=last_name,
                email=email,
                password=password
            )
            whatsapp_otp = generate_otp()
            email_otp = generate_otp()
            expiry = timezone.now() + timedelta(minutes=10)

            OTPLog.objects.bulk_create([
                OTPLog(user=user, code=whatsapp_otp, purpose='signup', sent_via='whatsapp', expires_at=expiry),
                OTPLog(user=user, code=email_otp, purpose='signup', sent_via='email', expires_at=expiry),
            ])

            SecurityLog.objects.create(
                user=user,
                event_type="Registration",
                ip_address=get_client_ip(request),
                user_agent=get_device_info(request),
                details="New user registered."
            )

            request.session['signup_whatsapp_otp'] = whatsapp_otp
            request.session['signup_email_otp'] = email_otp
            request.session['pending_signup'] = True
            request.session['pending_user'] = formatted_phone

    except IntegrityError as e:
        messages.error(request, "Database error during registration.")
        return render(request, 'core/register.html')

    def send_whatsapp():
        try:
            send_otp_via_whatsapp(formatted_phone, whatsapp_otp)
        except Exception as e:
            print(f"WhatsApp OTP error: {e}")

    def send_email_otp():
        try:
            subject = "Signup OTP"
            body = f"Hello {first_name},\nYour OTP is: {email_otp}\nIt expires in 10 minutes."
            send_otp_via_email([email], email_otp, subject=subject, body=body)
        except Exception as e:
            print(f"Email OTP error: {e}")

    threads = [
        threading.Thread(target=send_whatsapp, daemon=True),
        threading.Thread(target=send_email_otp, daemon=True)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    messages.success(request, "OTPs sent. Please verify your signup.")
    return redirect('verify-signup')


def verify_signup_view(request):
    pending_user = request.session.get('pending_user')
    pending_signup = request.session.get('pending_signup')

    if not pending_user or not pending_signup:
        messages.error(request, "Signup session expired. Please register again.")
        return redirect('register')

    try:
        user = User.objects.get(phone=pending_user)
    except User.DoesNotExist:
        messages.error(request, "User not found.")
        return redirect('register')

    if request.method == 'POST':
        entered_whatsapp = request.POST.get('otp-whatsapp', '').strip()
        entered_email = request.POST.get('otp-email', '').strip()

        if not entered_whatsapp or not entered_email:
            messages.error(request, "Enter both OTPs.")
            return render(request, 'core/verify-signup.html')

        try:
            whatsapp_otp_log = OTPLog.objects.get(user=user, purpose='signup', sent_via='whatsapp', verified=False)
            email_otp_log = OTPLog.objects.get(user=user, purpose='signup', sent_via='email', verified=False)
        except OTPLog.DoesNotExist:
            messages.error(request, "OTP records not found or already verified.")
            return redirect('register')

        if whatsapp_otp_log.is_expired():
            messages.error(request, "WhatsApp OTP expired. Please register again.")
            return redirect('register')

        if email_otp_log.is_expired():
            messages.error(request, "Email OTP expired. Please register again.")
            return redirect('register')

        if entered_whatsapp != whatsapp_otp_log.code:
            messages.error(request, "Invalid WhatsApp OTP.")
            return render(request, 'core/verify-signup.html')

        if entered_email != email_otp_log.code:
            messages.error(request, "Invalid Email OTP.")
            return render(request, 'core/verify-signup.html')

        whatsapp_otp_log.verified = True
        whatsapp_otp_log.verified_at = timezone.now()
        whatsapp_otp_log.save()

        email_otp_log.verified = True
        email_otp_log.verified_at = timezone.now()
        email_otp_log.save()

        for key in ['signup_whatsapp_otp', 'signup_email_otp', 'pending_signup', 'pending_user']:
            request.session.pop(key, None)

        SecurityLog.objects.create(
            user=user,
            event_type='Signup Verified',
            ip_address=get_client_ip(request),
            user_agent=get_device_info(request),
            details='User verified both WhatsApp and Email OTPs.'
        )

        messages.success(request, "Signup complete! You can now login.")
        return redirect('login')

    return render(request, 'core/verify-signup.html')
















#login views get data
def login_view(request):
    if request.method == 'POST':
        phone_input = request.POST.get("phone", "").strip()
        password = request.POST.get("password", "")
        ip = get_client_ip(request)
        device = get_device_info(request)
        #phone module
        try:
            parsed = phonenumbers.parse(phone_input, "KE")
            if not phonenumbers.is_valid_number(parsed):
                raise ValueError("Invalid number")
            formatted_phone = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        except Exception:
            messages.error(request, "Please enter a valid Kenyan phone number.")
            return render(request, 'core/login.html')
        # Check for brute-force
        recent_attempts = LoginAttempt.objects.filter(
            user__phone=formatted_phone,
            timestamp__gte=timezone.now() - timedelta(minutes=10)
        )
        failed_attempts = recent_attempts.filter(success=False).count()
        if failed_attempts > 5:
            messages.error(request, "Too many failed attempts. Try again later.")
            SecurityLog.objects.create(
                user=None,
                event_type="Brute Force Block",
                ip_address=ip,
                user_agent=device,
                details=f"More than 5 failed attempts for {formatted_phone}"
            )
            return render(request, 'core/access-denied.html')
        # Authenticate
        user = authenticate(request, username=formatted_phone, password=password)
        # Log the attempt
        if user:
            LoginAttempt.objects.create(
                user = user if user else None,
                ip_address=ip,
                device_info=device,
                success=bool(user)
            )
        if user:
            login(request, user)
            request.session['just_logged_in'] = True
            SecurityLog.objects.create(
                user=user,
                event_type='Login Success',
                ip_address=ip,
                user_agent=device,
                details='User logged in successfully.'
            )
            return redirect('verify-login')
        else:
            SecurityLog.objects.create(
                user=None,
                event_type='Login Failed',
                ip_address=ip,
                user_agent=device,
                details=f'Login failed for {formatted_phone}'
            )
            messages.error(request, "Invalid credentials.")
    return render(request, 'core/login.html')
#verify Login
@login_required
def verify_login_view(request):
    # Block direct access
    if not request.session.get('just_logged_in'):
        messages.error(request, "Access denied. Please login first.")
        return redirect('login')
    user = request.user
    # get otp
    if request.method == 'POST':
        entered_otp = request.POST.get('otp', '').strip()
        saved_otp = request.session.get('login_otp')
        if len(entered_otp) < 6 or len(entered_otp) > 7:
            messages.error(request, "OTP must be  6 digits.")
        elif entered_otp != saved_otp:
            # Log failed attempt
            SecurityLog.objects.create(
                user=user,
                event_type='OTP Failed',
                ip_address=get_client_ip(request),
                user_agent=get_device_info(request),
                details='Incorrect OTP during login.'
            )
            messages.error(request, "Invalid OTP.")
        else:
            # OTP verified
            request.session.pop('login_otp', None)
            request.session.pop('just_logged_in', None)
            #Log verified
            SecurityLog.objects.create(
                user=user,
                event_type='OTP Verified',
                ip_address=get_client_ip(request),
                user_agent=get_device_info(request),
                details='Login verified via OTP.',
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
    # gen OTP
    else:
        #Generate otp and create another session
        otp = generate_otp()
        request.session['login_otp'] = otp
        method = 'whatsapp'
        #By default, whatsapp else set
        try:
            method = user.profile.two_fa_method
        except Exception:
            messages.warning(request, "2FA method not set. Defaulting to WhatsApp.")
        try:
            if method == 'email':
                send_otp_via_email(user.email, otp)
                messages.success(request, f"OTP sent to your email: {user.email}")
            elif method == 'whatsapp':
                phone = user.phone.lstrip('0')
                send_otp_via_whatsapp(phone, otp)
                messages.success(request, f"OTP sent via WhatsApp: {phone}")
            else:
                raise ValueError("Unsupported 2FA method.")
            # Log OTP
            OTPLog.objects.create(
                user=user,
                code=otp,
                purpose='login',
                sent_via=method,
                expires_at=timezone.now() + timezone.timedelta(minutes=10)
            )
            print(f"[OTP SENT] {otp} via {method}")
        except Exception as e:
            messages.error(request, f"Failed to send OTP: {str(e)}")
    return render(request, 'core/verify-login.html')

