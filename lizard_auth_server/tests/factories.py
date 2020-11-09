# -*- coding: utf-8 -*-

from django.contrib.auth.models import User
from faker import Faker
from lizard_auth_server import models

import factory


fake = Faker()


class UserF(factory.django.DjangoModelFactory):
    class Meta:
        model = User

    username = factory.LazyAttribute(lambda x: fake.user_name())
    password = factory.LazyAttribute(lambda x: fake.password())
    # Note: normally you'd call
    # User.objects.create_user('someone', 'a@a.nl', 'pass')

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        user = model_class(*args, **kwargs)
        user.raw_password = user.password
        user.set_password(user.password)
        user.save()
        return user


class PortalF(factory.django.DjangoModelFactory):
    class Meta:
        model = models.Portal

    name = factory.LazyAttribute(lambda x: fake.company())
    redirect_url = factory.LazyAttribute(lambda x: fake.url())
    visit_url = factory.LazyAttribute(lambda x: fake.url())


class RoleF(factory.django.DjangoModelFactory):
    class Meta:
        model = models.Role
        django_get_or_create = ("name", "code")

    unique_id = factory.LazyAttribute(lambda role: models.create_new_uuid())

    name = "Some role"
    code = "somerole"

    external_description = "Buitenkant"
    internal_description = "Binnenkant"

    portal = factory.SubFactory(PortalF)


class TokenF(factory.django.DjangoModelFactory):
    class Meta:
        model = models.Token

    request_token = "Hard to guess token"
    portal = factory.SubFactory(PortalF)


class OrganisationF(factory.django.DjangoModelFactory):
    class Meta:
        model = models.Organisation

    name = factory.Sequence(lambda n: "organisation %s" % n)
    unique_id = factory.LazyAttribute(lambda org: models.create_new_uuid())


class UserProfileF(factory.django.DjangoModelFactory):
    class Meta:
        model = models.UserProfile
        django_get_or_create = ("user",)

    user = factory.SubFactory(UserF)
    # organisation = factory.SubFactory(OrganisationF)


class InvitationF(factory.django.DjangoModelFactory):
    class Meta:
        model = models.Invitation

    name = "Reinout"
    email = "reinout@example.org"
    organisation = "Some organisation"
    language = "nl"
