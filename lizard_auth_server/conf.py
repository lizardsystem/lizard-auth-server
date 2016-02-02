# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from datetime import timedelta

from appconf import AppConf
from django.conf import settings  # NOQA


class LizardAuthServerAppConf(AppConf):
    """Default values.

    These defaults may be overriden in the Django settings file of your
    project. In that case, don't forget to prefix them, for example:

    LIZARD_AUTH_SERVER_JWT_ALGORITHM = 'HS512'
    LIZARD_AUTH_SERVER_JWT_EXPIRATION_DELTA = timedelta(hours=12)

    """
    JWT_ALGORITHM = 'HS256'
    JWT_EXPIRATION_DELTA = timedelta(seconds=300)
