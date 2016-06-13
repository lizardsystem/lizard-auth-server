# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.conf import settings
from random import SystemRandom

import string


random = SystemRandom()
KEY_CHARACTERS = string.ascii_letters + string.digits


def default_gen_secret_key(length=40):
    return ''.join([random.choice(KEY_CHARACTERS) for _ in range(length)])


def gen_secret_key(length=40):
    generator = getattr(settings, 'SSO_KEYGENERATOR', default_gen_secret_key)
    return generator(length)
