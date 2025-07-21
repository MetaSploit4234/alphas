import random
from django.conf import settings
from django.core.mail import send_mail

# Random Numeric
def generate_otp(length=6):
    return ''.join(str(random.randint(0, 9)) for _ in range(length))

# via email
def send_otp_via_email(to_email, otp, subject="Your OTP", body=None):
    if not body:
        body = f"Your OTP is: {otp}"
    from_email = settings.EMAIL_HOST_USER
    try:
        print(f"Sending Email OTP to {to_email}: {otp}")
        send_mail(subject, body, from_email, [to_email])
        print("Email sent successfully.")
    except Exception as e:
        print(f"Failed to send email OTP to {to_email}: {e}")

# Clear session keys related to reset by email (you can add authenticator if needed)
def clear_reset_sessions(request, method='email'):
    session_keys = {
        'email': ['reset_email', 'reset_email_otp'],
        'authenticator': ['reset_auth_user'] 
    }.get(method, [])

    for key in session_keys:
        request.session.pop(key, None)


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def get_device_info(request):
    return request.META.get('HTTP_USER_AGENT', 'Unknown Device')
