from django.urls import path
from django.contrib.auth.decorators import login_required
from . import views

urlpatterns = [
    # Home / Index
    path('', views.index_view, name='index'),

    # Authentication
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),

    # OTP Verifications
    path('verify-signup/', views.verify_signup_view, name='verify-signup'),
    path('verify-login-by-authenticator/', views.verify_login_by_authenticator_view, name='verify-login-by-authenticator'),
    path('verify-login-by-email/', views.verify_login_by_email_view, name='verify-login-by-email'),
    path('verify-reset-email/', views.verify_reset_email_otp_view, name='verify-reset-email'),

    # Password recovery / reset
    path('select-reset-method/', views.select_reset_method_view, name='select-reset-method'),
    path('reset-by-email/', views.reset_by_email_view, name='reset-by-email'),
    path('reset-by-authenticator/', views.reset_by_authenticator_view, name='reset-by-authenticator'),
    path('update-password/', views.update_password_view, name='update-password'),
    path('update-2fa-method/', views.update_2fa_method_view, name='update-2fa-method'),

    # Password change (custom form)
    path('change-password/', views.change_password_view, name='change_password'),
    
    #access denied
    path('access-denied/', views.access_denied_view, name='access-denied'),
    # Admin Dashboard & tools
    path('admin-dashboard/', views.admin_dashboard_view, name='admin-dashboard'),
    path('admin-tools/elevate-roles/', views.admin_elevate_roles_view, name='admin-elevate-roles'),
    path('admin/otp-settings/', views.manage_otp_settings, name='manage_otp_settings'),
    path('admin/block-user/<int:user_id>/', views.block_user_view, name='block-user'),
    path('admin/unblock-user/<int:user_id>/', views.unblock_user_view, name='unblock-user'),

    # User Dashboard & profile
    path('user-dashboard/', views.user_dashboard, name='user-dashboard'),
    path('update-profile/', views.update_profile, name='update_profile'),

    # Security Dashboard
    path('security-dashboard/', views.security_dashboard_view, name='security-dashboard'),

    # Logs & OTP resend
    path('view-logs/', views.get_logs_api, name='view-logs'),
    path('resend-otp/', views.resend_otp_view, name='resend-otp'),

    # Settings
    path('settings/change-password/', views.change_password_view, name='change_password_alt'),
    path('settings/update-2fa/', views.update_2fa_method_view, name='update_2fa'),
    path('settings/notifications/', views.update_notifications_view, name='update_notifications'),

    # Dashboard general
    path('dashboard/', views.dashboard_view, name='dashboard'),

    # OTP reset method handler
    path('handle-reset-method/', views.handle_reset_method, name='handle-reset-method'),

    # Authenticator setup
    path('setup-authenticator/', views.setup_authenticator_view, name='setup-authenticator'),
]
