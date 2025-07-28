from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.conf import settings

class CustomUserManager(BaseUserManager):
    def create_user(self, phone, password=None, **extra_fields):
        if not phone:
            raise ValueError("Phone number is required")
        if not extra_fields.get('email'):
            raise ValueError("Email is required")
        user = self.model(phone=phone, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, phone, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(phone, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('user', 'User'),
        ('security', 'Security'),
    )

    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=20, unique=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='user')
    date_joined = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    totp_secret = models.CharField(max_length=32, blank=True, null=True)
    is_two_factor_enabled = models.BooleanField(default=False)
    authenticator_secret = models.CharField(max_length=32, blank=True, null=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'phone'
    REQUIRED_FIELDS = ['email', 'first_name', 'last_name']

    def __str__(self):
        return f"{self.phone} ({self.role})"

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"
        ordering = ['-date_joined']

class Profile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    TWO_FA_CHOICES = [
        ("email", "Email"),
        ("google", "Google Authenticator"),
    ]

    preferred_2fa_method = models.CharField(max_length=20, choices=TWO_FA_CHOICES, default="google")
    login_alerts = models.BooleanField(default=True)
    email_alerts = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.user.phone}'s Profile"

    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"

class OTPLog(models.Model):
    PURPOSE_CHOICES = (
        ('signup', 'Signup Verification'),
        ('login', 'Login Verification'),
        ('password_reset', 'Password Reset'),
        ('other', 'Other'),
    )

    METHOD_CHOICES = (
        ('email', 'Email'),
        ('google', 'Google Authenticator'),
    )

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='otp_logs')
    code = models.CharField(max_length=6)
    purpose = models.CharField(max_length=50, choices=PURPOSE_CHOICES, default='login')
    sent_via = models.CharField(max_length=20, choices=METHOD_CHOICES, default='google')
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    verified = models.BooleanField(default=False)
    verified_at = models.DateTimeField(null=True, blank=True)

    def save(self, *args, **kwargs):
        if not self.created_at:
            self.created_at = timezone.now()
        if not self.expires_at or self.expires_at <= self.created_at:
            self.expires_at = self.created_at + timezone.timedelta(minutes=10)
        super().save(*args, **kwargs)

    def is_expired(self):
        return timezone.now() > self.expires_at

    def __str__(self):
        status = "Verified" if self.verified else "Pending"
        return f"OTP {self.code} for {self.user.phone} ({self.purpose}) - {status}"

    class Meta:
        ordering = ['-created_at']
        verbose_name = "OTP Log"
        verbose_name_plural = "OTP Logs"

class LoginAttempt(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True, related_name='login_attempts')
    ip_address = models.GenericIPAddressField()
    device_info = models.TextField()
    success = models.BooleanField()
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        status = "Success" if self.success else "Failed"
        return f"{self.user.phone if self.user else 'Unknown'} | {status} | {self.ip_address} | {self.device_info} at {self.timestamp}"

    class Meta:
        ordering = ['-timestamp']
        verbose_name = "Login Attempt"
        verbose_name_plural = "Login Attempts"

class SecurityLog(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    event_type = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True, null=True)
    details = models.TextField(blank=True, null=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.phone if self.user else 'Anonymous'} | {self.event_type} at {self.timestamp}"

    class Meta:
        ordering = ['-timestamp']
        verbose_name = "Security Log"
        verbose_name_plural = "Security Logs"

class OTPSetting(models.Model):
    METHOD_CHOICES = [
        ('email', 'Email'),
        ('google', 'Google Authenticator')
    ]

    default_method = models.CharField(max_length=20, choices=METHOD_CHOICES, default='google')
    expiry_minutes = models.PositiveIntegerField(default=5)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"OTP Settings (Default: {self.default_method}, Expiry: {self.expiry_minutes} mins)"

    class Meta:
        verbose_name = "OTP Setting"
        verbose_name_plural = "OTP Settings"
