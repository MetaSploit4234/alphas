from django.core.management.base import BaseCommand
from django.utils import timezone
from core.models import OTPLog, SecurityLog
from django.contrib.auth import get_user_model

User = get_user_model()

class Command(BaseCommand):
    help = 'Delete users who never verified signup after OTP expiration.'

    def handle(self, *args, **kwargs):
        now = timezone.now()
        expired_otp_logs = OTPLog.objects.filter(
            purpose='Signup',
            expires_at__lt=now
        )

        user_ids = expired_otp_logs.values_list('user_id', flat=True).distinct()
        deleted_count = 0

        for user_id in user_ids:
            user = User.objects.filter(id=user_id).first()

            if not user:
                continue

            # Check if user already verified
            is_verified = SecurityLog.objects.filter(
                user=user,
                event_type='Signup Verified'
            ).exists()

            if not is_verified:
                # Log deletion before deleting user
                SecurityLog.objects.create(
                    user=user,
                    event_type="Unverified User Auto-Deletion",
                    ip_address="system",
                    user_agent="system",
                    details="User deleted after OTP expired without verification."
                )
                print(f"Deleting unverified user: {user.phone} (ID: {user.id})")
                user.delete()
                deleted_count += 1

        self.stdout.write(self.style.SUCCESS(f"{deleted_count} unverified users deleted."))
