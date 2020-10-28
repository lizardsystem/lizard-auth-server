# -*- coding: utf-8 -*-


DEBUG = True
DATABASES = {
    "default": {
        "NAME": ":memory:",
        "ENGINE": "django.db.backends.sqlite3",
        "USER": "",
        "PASSWORD": "",
        "PORT": "",
    }
}


# Almost always set to 1.  Django allows multiple sites in one database.
SITE_ID = 1

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
ROOT_URLCONF = "lizard_auth_server.urls"
TEST_RUNNER = "django_nose.NoseTestSuiteRunner"

TEMPLATE_CONTEXT_PROCESSORS = (
    "django.contrib.auth.context_processors.auth",
    "django.contrib.messages.context_processors.messages",
    "django.core.context_processors.debug",
    "django.core.context_processors.i18n",
    "django.core.context_processors.media",
    "django.core.context_processors.static",
    "django.core.context_processors.request",
)

MIDDLEWARE_CLASSES = (
    # Gzip needs to be at the top.
    "django.middleware.gzip.GZipMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "tls.TLSRequestMiddleware",
)

INSTALLED_APPS = (
    "lizard_auth_server",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.messages",
    "django.contrib.sessions",
    "django.contrib.sites",
    "django.contrib.staticfiles",
    "django_extensions",
)
