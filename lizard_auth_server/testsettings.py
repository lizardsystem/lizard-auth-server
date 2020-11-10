# -*- coding: utf-8 -*-
import os


SETTINGS_DIR = os.path.dirname(os.path.realpath(__file__))

BUILDOUT_DIR = os.path.abspath(os.path.join(SETTINGS_DIR, ".."))

LOGGING = {
    "version": 1,
    "disable_existing_loggers": True,
    "formatters": {
        "simple": {"format": "%(levelname)s %(message)s"},
        "verbose": {"format": "%(asctime)s %(name)s %(levelname)s\n%(message)s"},
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "simple",
            "level": None,
        },
        "logfile": {
            "class": "logging.FileHandler",
            "filename": os.path.join(BUILDOUT_DIR, "var", "log", "django.log"),
            "formatter": "verbose",
            "level": "WARN",
        },
        "null": {"class": "logging.NullHandler", "level": "DEBUG"},
    },
    "loggers": {
        "": {"handlers": ["console"], "level": "DEBUG", "propagate": True},
        "django.request": {
            "handlers": ["console", "logfile"],
            "propagate": False,
            "level": "WARN",  # WARN also shows 404 errors
        },
        "django.db.backends": {
            "handlers": ["null"],
            "level": "WARN",
            "propagate": False,
        },
        "factory": {"handlers": ["null"], "level": "DEBUG", "propagate": False},
        "faker": {"handlers": ["null"], "level": "DEBUG", "propagate": False},
    },
}

DEBUG = True

# ADMINS get internal error mails, MANAGERS get 404 mails.
ADMINS = (
    # ('Your Name', 'your_email@domain.com'),
)
MANAGERS = ADMINS

INSIDE_DOCKER = os.path.exists(os.path.join(os.getcwd(), "..", ".dockerenv"))

DATABASES = {
    "default": {
        "NAME": "sso",
        "ENGINE": "django.db.backends.postgresql_psycopg2",
        "USER": "buildout",
        "PASSWORD": "buildout",
        "HOST": (INSIDE_DOCKER and "db" or "localhost"),
        "PORT": 5432,
    }
}

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "DEBUG": True,
    },
]

# Almost always set to 1.  Django allows multiple sites in one database.
SITE_ID = 1

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name although not all
# choices may be available on all operating systems.  If running in a Windows
# environment this must be set to the same as your system time zone.
USE_TZ = True
TIME_ZONE = "Europe/Amsterdam"

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = "nl-NL"
# For at-runtime language switching.  Note: they're shown in reverse order in
# the interface!
LANGUAGES = (
    ("en", "English"),
    ("nl", "Nederlands"),
)
# If you set this to False, Django will make some optimizations so as not to
# load the internationalization machinery.
USE_I18N = True
USE_L10N = True

# Absolute path to the directory that holds user-uploaded media.
MEDIA_ROOT = os.path.join(BUILDOUT_DIR, "var", "media")
# Absolute path to the directory where django-staticfiles'
# "bin/django build_static" places all collected static files from all
# applications' /media directory.
STATIC_ROOT = os.path.join(BUILDOUT_DIR, "var", "static")

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash if there is a path component (optional in other cases).
MEDIA_URL = "/media/"
# URL for the per-application /media static files collected by
# django-staticfiles.  Use it in templates like
# "{{ MEDIA_URL }}mypackage/my.css".
STATIC_URL = "/static_media/"

SECRET_KEY = "This is not secret but that is ok."

# SSO
SSO_TOKEN_TIMEOUT_MINUTES = 30
JWT_EXPIRATION_MINUTES = 5

# Invitation / activation
# Activation keys expire after this timedelta
ACCOUNT_ACTIVATION_DAYS = 7
# Prefix used to generate absolute links to this site. Note: should NOT end
# with a slash.  Used in emails.
SITE_PUBLIC_URL_PREFIX = "http://127.0.0.1:8001"
# Name of this site, for use in email subjects et cetera
SITE_NAME = "sso.lizard.net"

ROOT_URLCONF = "lizard_auth_server.urls"

TEST_RUNNER = "django_nose.NoseTestSuiteRunner"

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.filebased.FileBasedCache",
        "LOCATION": os.path.join(BUILDOUT_DIR, "var", "cache"),
    }
}

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                # Default list above.
                "django.template.context_processors.i18n",
                "django.template.context_processors.media",
                "django.template.context_processors.static",
            ]
        },
    },
]


MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # Default list above.
    "django.middleware.locale.LocaleMiddleware",
]

INSTALLED_APPS = [
    "lizard_auth_server",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.messages",
    "django.contrib.sessions",
    "django.contrib.sites",
    "django.contrib.staticfiles",
    "oidc_provider",
    "django_extensions",
]

DEFAULT_FROM_EMAIL = "noreply@nelen-schuurmans.nl"
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
OIDC_USERINFO = "lizard_auth_server.oidc.userinfo"
