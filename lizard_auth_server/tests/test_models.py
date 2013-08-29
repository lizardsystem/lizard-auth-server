import factory

from django.contrib.auth.models import User
from django.test import TestCase

from lizard_auth_server import models


class UserF(factory.Factory):
    FACTORY_FOR = User

    username = factory.Sequence(lambda n: 'testuser{0}'.format(n))


class PortalF(factory.DjangoModelFactory):
    FACTORY_FOR = models.Portal

    name = 'Some portal'
    redirect_url = 'http://www.lizard.net/'
    visit_url = 'http://www.lizard.net/'


class RoleF(factory.DjangoModelFactory):
    FACTORY_FOR = models.Role
    FACTORY_DJANGO_GET_OR_CREATE = ('name', 'code')
    unique_id = factory.LazyAttribute(lambda role: models.create_new_uuid())

    name = 'Some role'
    code = 'somerole'

    external_description = 'Buitenkant'
    internal_description = 'Binnenkant'

    portal = factory.SubFactory(PortalF)


class OrganisationF(factory.DjangoModelFactory):
    FACTORY_FOR = models.Organisation

    name = 'Organisatienaam'
    unique_id = factory.LazyAttribute(lambda org: models.create_new_uuid())


class UserProfileF(factory.Factory):
    FACTORY_FOR = models.UserProfile
    FACTORY_DJANGO_GET_OR_CREATE = ('user',)

    user = factory.SubFactory(UserF)
    organisation = factory.SubFactory(OrganisationF)


class TestUserProfile(TestCase):
    def test_without_setup_all_organisation_roles_empty(self):
        profile = models.UserProfile()
        self.assertEquals(
            len(list(profile.all_organisation_roles())), 0)

    def test_role_for_all_members_is_returned(self):
        user = UserF.create(username='newuser')
        org = OrganisationF.create()
        role = RoleF.create()

        models.OrganisationRole.objects.create(
            organisation=org, role=role, for_all_users=True)

        profile = models.UserProfile.objects.fetch_for_user(user)
        profile.organisations.add(org)

        self.assertEquals(
            len(list(profile.all_organisation_roles())), 1)

    def test_role_for_user_is_returned(self):
        user = UserF.create(username='newuser2')
        org = OrganisationF.create()
        role = RoleF.create()

        orgrole = models.OrganisationRole.objects.create(
            organisation=org, role=role, for_all_users=False)

        profile = models.UserProfile.objects.fetch_for_user(user)
        self.assertEquals(
            len(list(profile.all_organisation_roles())), 0)

        profile.roles.add(orgrole)

        self.assertEquals(
            len(list(profile.all_organisation_roles())), 1)

    def test_they_are_not_both_returned(self):
        user = UserF.create(username='newuser')
        org = OrganisationF.create()
        role = RoleF.create()

        orgrole = models.OrganisationRole.objects.create(
            organisation=org, role=role, for_all_users=True)

        profile = models.UserProfile.objects.fetch_for_user(user)
        profile.organisations.add(org)
        profile.roles.add(orgrole)

        self.assertEquals(
            len(list(profile.all_organisation_roles())), 1)
