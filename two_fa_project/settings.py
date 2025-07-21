from pathlib import Path
import os
BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
SECRET_KEY = 'django-insecure-^qb-37_6x$*+d)nqlljsta9x_-c3b)t(hb*iw&-3jn*)dgci-8'

DEBUG = True

ALLOWED_HOSTS = [
    'twofaproject-gqbsefhfc5gfe0fn.canadacentral-01.azurewebsites.net',
    'localhost',
    '127.0.0.1'
]


AUTH_USER_MODEL = 'core.CustomUser'


# Email Configuration
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'kipngetichsalaton@gmail.com'
EMAIL_HOST_PASSWORD = 'cdtoneiopntoffnd'


# Installed Applications
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'core',
    'django_browser_reload',
    'django_crontab',
]


# Middleware Configuration
MIDDLEWARE = [
    ''
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django_browser_reload.middleware.BrowserReloadMiddleware',
]


# URL Configuration
ROOT_URLCONF = 'two_fa_project.urls'

#Templates Configuration
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'core' / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        }, 
        
    },
]


WSGI_APPLICATION = 'two_fa_project.wsgi.application'

#redirection

LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/user-dashboard/'
LOGOUT_REDIRECT_URL = '/login/'

# MySQL Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'two_fa_project',
        'USER': 'root',
        'PASSWORD': 'salaa',
        'HOST': '127.0.0.1',
        'PORT': '3001',
    }
}

# Password Validators
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Localization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static Files
STATIC_URL = 'static/'

# Default Primary Key
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'