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
    def test_organisation_can_return_none(self):
        user = UserF.create()
        profile = models.UserProfile.objects.fetch_for_user(user)
        self.assertEquals(profile.organisation, None)

    def test_without_setup_all_organisation_roles_empty(self):
        portal = PortalF.create()
        profile = models.UserProfile()
        self.assertEquals(
            len(list(profile.all_organisation_roles(portal))), 0)

    def test_role_for_all_members_is_returned(self):
        portal = PortalF.create()
        user = UserF.create(username='newuser')
        org = OrganisationF.create()
        role = RoleF.create(portal=portal)

        models.OrganisationRole.objects.create(
            organisation=org, role=role, for_all_users=True)

        profile = models.UserProfile.objects.fetch_for_user(user)
        profile.organisations.add(org)

        self.assertEquals(
            len(list(profile.all_organisation_roles(portal))),
            1)

    def test_role_for_user_is_returned(self):
        portal = PortalF.create()
        user = UserF.create(username='newuser2')
        org = OrganisationF.create()
        role = RoleF.create(portal=portal)

        orgrole = models.OrganisationRole.objects.create(
            organisation=org, role=role, for_all_users=False)

        profile = models.UserProfile.objects.fetch_for_user(user)
        self.assertEquals(
            len(list(profile.all_organisation_roles(portal))), 0)

        profile.roles.add(orgrole)

        self.assertEquals(
            len(list(profile.all_organisation_roles(portal))), 1)

    def test_they_are_not_both_returned(self):
        portal = PortalF.create()
        user = UserF.create(username='newuser')
        org = OrganisationF.create()
        role = RoleF.create(portal=portal)

        orgrole = models.OrganisationRole.objects.create(
            organisation=org, role=role, for_all_users=True)

        profile = models.UserProfile.objects.fetch_for_user(user)
        profile.organisations.add(org)
        profile.roles.add(orgrole)

        self.assertEquals(
            len(list(profile.all_organisation_roles(portal))), 1)

    def test_only_the_given_portal_is_returned(self):
        portal1 = PortalF.create(name='portal1')
        portal2 = PortalF.create(name='portal2')
        portal3 = PortalF.create(name='portal3')

        role1 = RoleF.create(name='role1', portal=portal1)
        role2 = RoleF.create(name='role2', portal=portal2)
        role3 = RoleF.create(name='role3', portal=portal2)  # Note: 2, not 3

        user = UserF.create(username='newuser')
        org = OrganisationF.create()

        orgrole1 = models.OrganisationRole.objects.create(
            organisation=org, role=role1, for_all_users=True)
        orgrole2 = models.OrganisationRole.objects.create(
            organisation=org, role=role2, for_all_users=True)
        orgrole3 = models.OrganisationRole.objects.create(
            organisation=org, role=role3, for_all_users=True)

        profile = models.UserProfile.objects.fetch_for_user(user)
        profile.organisations.add(org)

        profile.roles.add(orgrole1)
        profile.roles.add(orgrole2)
        profile.roles.add(orgrole3)

        self.assertEquals(
            len(list(profile.all_organisation_roles(portal1))), 1)
        self.assertEquals(
            len(list(profile.all_organisation_roles(portal2))), 2)
        self.assertEquals(
            len(list(profile.all_organisation_roles(portal3))), 0)
