from __future__ import unicode_literals
from django.contrib.auth.models import User
from lizard_auth_server import models

import factory


class UserF(factory.DjangoModelFactory):
    class Meta:
        model = User

    username = factory.Sequence(lambda n: 'testuser{0}'.format(n))
    # Note: normally you'd call
    # User.objects.create_user('someone', 'a@a.nl', 'pass')


class PortalF(factory.DjangoModelFactory):
    class Meta:
        model = models.Portal

    name = 'Some portal'
    redirect_url = 'http://default.portal.net/'
    visit_url = 'http://www.portal.net/'
    allowed_domain = ''


class RoleF(factory.DjangoModelFactory):
    class Meta:
        model = models.Role
        django_get_or_create = ('name', 'code')

    unique_id = factory.LazyAttribute(lambda role: models.create_new_uuid())

    name = 'Some role'
    code = 'somerole'

    external_description = 'Buitenkant'
    internal_description = 'Binnenkant'

    portal = factory.SubFactory(PortalF)


class TokenF(factory.DjangoModelFactory):
    class Meta:
        model = models.Token

    request_token = 'Hard to guess token'
    portal = factory.SubFactory(PortalF)


class OrganisationF(factory.DjangoModelFactory):
    class Meta:
        model = models.Organisation

    name = factory.Sequence(lambda n: 'organisation %s' % n)
    unique_id = factory.LazyAttribute(lambda org: models.create_new_uuid())


class UserProfileF(factory.DjangoModelFactory):
    class Meta:
        model = models.UserProfile
        django_get_or_create = ('user',)

    user = factory.SubFactory(UserF)
    organisation = factory.SubFactory(OrganisationF)


class InvitationF(factory.DjangoModelFactory):
    class Meta:
        model = models.Invitation

    name = 'Reinout'
    email = 'reinout@example.org'
    organisation = 'Some organisation'
    language = 'nl'
