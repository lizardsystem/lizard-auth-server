# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from django.contrib.auth.models import User
from faker import Factory as FakerFactory
import factory

from lizard_auth_server import models


faker = FakerFactory.create()


class UserF(factory.DjangoModelFactory):
    class Meta:
        model = User

    username = factory.LazyAttribute(lambda x: faker.user_name())
    password = factory.LazyAttribute(lambda x: faker.password())
    # Note: normally you'd call
    # User.objects.create_user('someone', 'a@a.nl', 'pass')

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        user = model_class(*args, **kwargs)
        user.raw_password = user.password
        user.set_password(user.password)
        user.save()
        return user


class PortalF(factory.DjangoModelFactory):
    class Meta:
        model = models.Portal

    name = factory.LazyAttribute(lambda x: faker.company())
    redirect_url = factory.LazyAttribute(lambda x: faker.url())
    visit_url = factory.LazyAttribute(lambda x: faker.url())


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


class CompanyF(factory.DjangoModelFactory):
    class Meta:
        model = models.Company

    name = factory.Sequence(lambda n: 'company %s' % n)
    unique_id = factory.LazyAttribute(lambda org: models.create_new_uuid())

    @factory.post_generation
    def guests(self, create, extracted, **kwargs):
        if not create:
            return
        if extracted:
            # A list of companies were passed in, use them
            for guest in extracted:
                self.guests.add(guest)


class ProfileF(factory.DjangoModelFactory):
    class Meta:
        model = models.Profile
        django_get_or_create = ('user',)

    user = factory.SubFactory(UserF)
    company = factory.SubFactory(CompanyF)


class SiteF(factory.DjangoModelFactory):
    class Meta:
        model = models.Site

    name = factory.LazyAttribute(lambda x: faker.company())
    redirect_url = factory.LazyAttribute(lambda x: faker.url())
    visit_url = factory.LazyAttribute(lambda x: faker.url())

    @factory.post_generation
    def available_to(self, create, extracted, **kwargs):
        if not create:
            return
        if extracted:
            # A list of companies were passed in, use them
            for company in extracted:
                self.available_to.add(company)
