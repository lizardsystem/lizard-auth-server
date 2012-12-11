# -*- coding: utf-8 -*-
# Copyright 2011 Nelen & Schuurmans
import logging
import datetime

from django.core.management.base import BaseCommand
from django.conf import settings
from lizard_auth_server.models import Token 

logger = logging.getLogger(__name__)

TOKEN_TIMEOUT = datetime.timedelta(minutes=settings.SSO_TOKEN_TIMEOUT_MINUTES)

class Command(BaseCommand):
    args = ""
    help = "Clear expired SSO tokens from the database."

    def handle(self, *args, **options):
        max_age = datetime.datetime.now(tz=pytz.UTC) - TOKEN_TIMEOUT
        Token.objects.filter(created__lt=max_age).delete()
