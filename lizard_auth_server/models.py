# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import datetime

from django.db import models
from django.db import transaction
from django.contrib.auth.models import User
from django.db.models.query_utils import Q
from django.db.models.loading import get_model
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils import translation
from django.core.exceptions import ValidationError

import pytz

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

class Token(models.Model):
    """
    An auth token used to authenticate a user.
    """
    portal = models.ForeignKey(Portal)
    request_token = models.CharField(max_length=64, unique=True)
    auth_token = models.CharField(max_length=64, unique=True)
    user = models.ForeignKey(User, null=True)
    created = models.DateTimeField(default=(lambda: datetime.datetime.now(tz=pytz.UTC)))

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
    '''
    Note: when migrating to Django 1.5, this is the ideal candidate
    for using the new custom User model features.
    '''
    user = models.ForeignKey(User, null=False, unique=True)
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

    objects = UserProfileManager()

    def __unicode__(self):
        if self.user:
            return 'UserProfile {} ({}, {})'.format(self.pk, self.user, self.user.email)
        else:
            return 'UserProfile {}'.format(self.pk)

    @property
    def username(self):
        return self.user.username

    @property
    def full_name(self):
        return self.user.get_full_name()

    @property
    def first_name(self):
        return self.user.first_name

    @property
    def last_name(self):
        return self.user.last_name

    @property
    def email(self):
        return self.user.email

    @property
    def is_active(self):
        '''
        Returns True when the account is active, meaning the User has not been
        deactivated by an admin.

        Note: unrelated to account activation.
        '''
        return self.user.is_active

class Invitation(models.Model):
    name = models.CharField(max_length=255, null=False, blank=False)
    email = models.EmailField(null=False, blank=False)
    language = models.CharField(max_length=16, null=False, blank=False)
    portals = models.ManyToManyField(Portal, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    activation_key = models.CharField(max_length=64, null=True, blank=True, unique=True)
    activation_key_date = models.DateTimeField(null=True, blank=True,
        help_text='Date on which the activation key was generated. Used for expiration.'
    )
    is_activated = models.BooleanField(default=False)
    activated_on = models.DateTimeField(null=True, blank=True)
    user = models.ForeignKey(User, null=True, blank=True)
    profile = models.ForeignKey(UserProfile, null=True, blank=True)

    def __unicode__(self):
        if self.profile:
            return '{}, {}'.format(self.profile.user, self.profile.email)
        else:
            return '{}, {} (Not activated)'.format(self.name, self.email)

    def clean(self):
        if self.is_activated:
            if self.activation_key:
                raise ValidationError('Invitation is marked as activated, but there is still an activation key set.')
            if self.profile is None:
                raise ValidationError('Invitation is marked as activated, but its profile isnt set.')
            if self.activated_on is None:
                raise ValidationError('Invitation is marked as activated, but its field "activated_on" isnt set.')

    def _rotate_activation_key(self):
        if self.is_activated:
            raise Exception('user is already activated')

        # generate a new activation key
        self.activation_key = gen_key(Invitation, 'activation_key')()

        # update key date so we can check for expiration
        self.activation_key_date = datetime.datetime.now(tz=pytz.UTC)
        self.save()

    def send_new_activation_email(self):
        if self.is_activated:
            raise Exception('user is already activated')

        # generate a fresh key
        self._rotate_activation_key()

        ### send this user an email containing the key
        # build a render context for the email template 
        expiration_date = datetime.datetime.now(tz=pytz.UTC) + datetime.timedelta(days=settings.ACCOUNT_ACTIVATION_DAYS)
        ctx_dict = {
            'name': self.name,
            'activation_key': self.activation_key,
            'expiration_days': settings.ACCOUNT_ACTIVATION_DAYS,
            'expiration_date': expiration_date,
            'site_name': settings.SITE_NAME,
            'site_public_url_prefix': settings.SITE_PUBLIC_URL_PREFIX,
            'invitation': self,
        }

        # switch to the users language
        old_lang = translation.get_language()
        translation.activate(self.language)

        # render the email subject and message using Django's templating
        subject = render_to_string('lizard_auth_server/invitation_email_subject.txt', ctx_dict)
        # ensure email subject doesn't contain newlines
        subject = ''.join(subject.splitlines())
        message = render_to_string('lizard_auth_server/invitation_email.html', ctx_dict)

        # switch language back
        translation.activate(old_lang)

        # send the actual email
        send_mail(subject, message, None, [self.email])

    def create_user(self, data):
        with transaction.commit_on_success():
            # create the Django auth user
            user = User.objects.create_user(
                username=data['username'],
                email=data['email'],
                password=data['new_password1']
            )

            # immediately deactivate this user, no way to do this directly
            user.is_active = False
            user.save()

            # link the new user to the invitation
            self.user = user
            self.save()

    def activate(self, data):
        with transaction.commit_on_success():
            user = self.user

            # create and fill the profile
            profile = UserProfile()
            profile.title = data['title']
            profile.street = data['street']
            profile.postal_code =data['postal_code']
            profile.town = data['town']
            profile.phone_number = data['phone_number']
            profile.mobile_phone_number = data['mobile_phone_number']
            profile.user = user
            profile.save()

            # many-to-many, so save these after profile has been assigned an ID
            profile.portals = self.portals.all()
            profile.save()

            # set the additional attributes on the user model,
            # and mark it as active
            user.is_active = True
            user.first_name = data['first_name']
            user.last_name = data['last_name']
            user.save()

            # link the profile to the invitation so we have a trail
            # from invitation to user
            self.profile = profile

            # clear now invalid activation key
            self.activation_key = None
            self.activated_on = datetime.datetime.now(tz=pytz.UTC)
            self.is_activated = True
            self.save()
