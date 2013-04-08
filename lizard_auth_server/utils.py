# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from random import SystemRandom
from django.conf import settings
import string


# Note: the code in this module must be identical in both lizard-auth-server
# and lizard-auth-client!

random = SystemRandom()
KEY_CHARACTERS = string.letters + string.digits

# Keys that can be directly copied from the User object and passed to the
# client.
SIMPLE_KEYS = [
    'pk',
    'username',
    'first_name',
    'last_name',
    'email',
    'is_active',
    'is_staff',
    'is_superuser',
]


def default_gen_secret_key(length=40):
    return ''.join([random.choice(KEY_CHARACTERS) for _ in range(length)])


def gen_secret_key(length=40):
    generator = getattr(settings, 'SSO_KEYGENERATOR', default_gen_secret_key)
    return generator(length)
