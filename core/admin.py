from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django import forms
from .models import CustomUser, OTPLog, SecurityLog, LoginAttempt

# --- Custom User Form to expose 'role' in admin ---
class CustomUserChangeForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = '__all__'

# --- Custom User Admin ---
@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    form = CustomUserChangeForm
    model = CustomUser

    list_display = ('phone', 'email', 'role', 'is_staff', 'is_active')
    list_filter = ('role', 'is_staff', 'is_active')
    search_fields = ('phone', 'email', 'first_name', 'last_name')
    ordering = ('phone',)

    # Extending fieldsets to add phone and role on user edit page
    fieldsets = UserAdmin.fieldsets + (
        (None, {'fields': ('phone', 'role')}),
    )

    # Fields visible when creating a user
    add_fieldsets = UserAdmin.add_fieldsets + (
        (None, {
            'classes': ('wide',),
            'fields': ('phone', 'role'),
        }),
    )

# --- OTPLog Admin ---
@admin.register(OTPLog)
class OTPLogAdmin(admin.ModelAdmin):
    list_display = ('get_phone', 'code', 'purpose', 'sent_via', 'created_at', 'expires_at', 'verified')
    list_filter = ('purpose', 'sent_via', 'verified', 'created_at')
    search_fields = ('user__phone', 'code')

    def get_phone(self, obj):
        return obj.user.phone
    get_phone.short_description = 'Phone'
    get_phone.admin_order_field = 'user__phone'  # allows column sorting

# --- SecurityLog Admin ---
@admin.register(SecurityLog)
class SecurityLogAdmin(admin.ModelAdmin):
    list_display = ('get_phone', 'event_type', 'ip_address', 'timestamp')
    list_filter = ('event_type', 'timestamp')
    search_fields = ('user__phone', 'ip_address', 'event_type')

    def get_phone(self, obj):
        return obj.user.phone if obj.user else "Anonymous"
    get_phone.short_description = 'Phone'
    get_phone.admin_order_field = 'user__phone'

# --- LoginAttempt Admin ---
@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ('get_phone', 'ip_address', 'device_info', 'success', 'timestamp')
    list_filter = ('success', 'timestamp')
    search_fields = ('user__phone', 'ip_address', 'device_info')

    def get_phone(self, obj):
        return obj.user.phone
    get_phone.short_description = 'Phone'

