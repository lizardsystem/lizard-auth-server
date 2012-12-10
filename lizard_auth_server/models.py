# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import datetime

from django.db import models
from django.contrib.auth.models import User
from django.db.models.query_utils import Q
from django.db.models.loading import get_model
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils import translation

from lizard_auth_server.utils import gen_secret_key


def gen_key(model, field):
    """
    Helper function to give a unique default value to the selected
    field in a model.
    """
    def _genkey():
        if isinstance(model, basestring):
            ModelClass = get_model('lizard_auth_server', model)
            if not ModelClass:
                raise Exception('Unknown model {}'.format(model))
        else:
            ModelClass = model
        key = gen_secret_key(64)
        while ModelClass.objects.filter(**{field: key}).exists():
            key = gen_secret_key(64)
        return key
    return _genkey

class TokenManager(models.Manager):
    def create_for_portal(self, portal):
        """
        Create a new token for a portal object.
        """
        request_token = gen_secret_key(64)
        auth_token = gen_secret_key(64)
        # check unique constraints
        while self.filter(Q(request_token=request_token) | Q(auth_token=auth_token)).exists():
            request_token = gen_secret_key(64)
            auth_token = gen_secret_key(64)
        return self.create(
            portal=portal,
            request_token=request_token,
            auth_token=auth_token,
        )

class Portal(models.Model):
    """
    A portal. If secret/key change, the portal website has to be updated too!
    """
    name = models.CharField(max_length=255, null=False, blank=False, help_text='Name used to refer to this portal.')
    sso_secret = models.CharField(max_length=64, unique=True, default=gen_key('Portal', 'sso_secret'), help_text='Secret shared between SSO client and server to sign/encrypt communication.')
    sso_key = models.CharField(max_length=64, unique=True, default=gen_key('Portal', 'sso_key'), help_text='String used to identify the SSO client.')
    redirect_url = models.CharField(max_length=255, help_text='URL used in the SSO redirection.')
    visit_url = models.CharField(max_length=255, help_text='URL used in the UI to refer to this portal.')
    
    def __unicode__(self):
        return '{} ({})'.format(self.name, self.visit_url)
    
    def rotate_keys(self):
        self.sso_secret = gen_key(Portal, 'sso_secret')()
        self.sso_key = gen_key(Portal, 'sso_key')()
        self.save()

class Token(models.Model):
    """
    An auth token used to authenticate a user.
    """
    portal = models.ForeignKey(Portal)
    request_token = models.CharField(max_length=64, unique=True)
    auth_token = models.CharField(max_length=64, unique=True)
    user = models.ForeignKey(User, null=True)
    created = models.DateTimeField(default=datetime.datetime.now)

    objects = TokenManager()

class UserProfileManager(models.Manager):
    def fetch_for_user(self, user):
        if user is None:
            raise AttributeError('Cant get UserProfile for user=None')
        return self.get(user=user)

    def create_deactivated(self, activation_name, activation_email, activation_language, organisation, portals):
        p = UserProfile()
        p.activation_name = activation_name
        p.activation_email = activation_email
        p.activation_language = activation_language
        p.organisation = organisation
        p.save()
        p.portals = portals
        return p

class UserProfile(models.Model):
    user = models.ForeignKey(User, null=True, unique=True)
    portals = models.ManyToManyField(Portal, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    organisation = models.CharField(max_length=255, null=True, blank=True)
    title = models.CharField(max_length=255, null=True, blank=True)
    street = models.CharField(max_length=255, null=True, blank=True)
    postal_code = models.CharField(max_length=255, null=True, blank=True)
    town = models.CharField(max_length=255, null=True, blank=True)
    phone_number = models.CharField(max_length=255, null=True, blank=True)
    mobile_phone_number = models.CharField(max_length=255, null=True, blank=True)
    is_activated = models.BooleanField(default=False)
    activated_on = models.DateTimeField(null=True)
    activation_name = models.CharField(max_length=255, null=True, blank=True)
    activation_email = models.EmailField(null=False, blank=False)
    activation_language = models.CharField(max_length=16, null=False, blank=False)
    activation_key = models.CharField(max_length=64, null=True, blank=True, unique=True)
    activation_key_date = models.DateTimeField(null=True,
        help_text='Date on which the activation key was generated. Used for expiration.'
    )

    objects = UserProfileManager()

    def __unicode__(self):
        if self.user is None:
            return '{}, {} (Not activated)'.format(self.activation_name, self.activation_email)
        else:
            return '{}, {}'.format(self.user, self.user.email)

    @property
    def username(self):
        return self.user.username if self.user else ''

    @property
    def first_name(self):
        return self.user.first_name if self.user else ''

    @property
    def last_name(self):
        return self.user.last_name if self.user else ''

    @property
    def email(self):
        if self.user is None:
            return self.activation_email
        else:
            return self.user.email

    @property
    def is_active(self):
        if self.user is None:
            return False
        else:
            return self.user.is_active

    def rotate_activation_key(self):
        if self.is_activated:
            raise Exception('user is already activated')

        # generate a new activation key
        self.activation_key = gen_key(UserProfile, 'activation_key')()

        # update key date so we can check for expiration
        self.activation_key_date = datetime.datetime.now()
        self.save()

    def send_new_activation_email(self):
        if self.is_activated:
            raise Exception('user is already activated')

        # generate a fresh key
        self.rotate_activation_key()

        # send this user an email containing the key
        expiration_date = datetime.datetime.now() + datetime.timedelta(days=settings.ACCOUNT_ACTIVATION_DAYS)
        ctx_dict = {
            'name': self.activation_name,
            'activation_key': self.activation_key,
            'expiration_days': settings.ACCOUNT_ACTIVATION_DAYS,
            'expiration_date': expiration_date,
            'site_name': settings.SITE_NAME,
            'site_public_url_prefix': settings.SITE_PUBLIC_URL_PREFIX,
            'registered_profile': self,
        }
        # switch to the users language
        old_lang = translation.get_language()
        translation.activate(self.activation_language)

        subject = render_to_string('lizard_auth_server/activation_email_subject.txt', ctx_dict)
        # Email subject *must not* contain newlines
        subject = ''.join(subject.splitlines())
        message = render_to_string('lizard_auth_server/activation_email.html', ctx_dict)

        # switch language back
        translation.activate(old_lang)

        # send the actual email
        send_mail(subject, message, None, [self.activation_email])
