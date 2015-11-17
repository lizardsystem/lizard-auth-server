from __future__ import unicode_literals
from django.test import TestCase
from lizard_auth_server import models
from lizard_auth_server.tests import factories


class TestUserProfile(TestCase):

    def test_organisation_can_return_none(self):
        user = factories.UserF.create()
        profile = models.UserProfile.objects.fetch_for_user(user)
        self.assertEquals(profile.organisation, None)

    def test_without_setup_all_organisation_roles_empty(self):
        portal = factories.PortalF.create()
        profile = models.UserProfile()
        self.assertEquals(
            len(list(profile.all_organisation_roles(portal))), 0)

    def test_role_for_all_members_is_returned(self):
        portal = factories.PortalF.create()
        user = factories.UserF.create(username='newuser')
        org = factories.OrganisationF.create()
        role = factories.RoleF.create(portal=portal)

        models.OrganisationRole.objects.create(
            organisation=org, role=role, for_all_users=True)

        profile = models.UserProfile.objects.fetch_for_user(user)
        profile.organisations.add(org)

        self.assertEquals(
            len(list(profile.all_organisation_roles(portal))),
            1)

    def test_role_for_user_is_returned(self):
        portal = factories.PortalF.create()
        user = factories.UserF.create(username='newuser2')
        org = factories.OrganisationF.create()
        role = factories.RoleF.create(portal=portal)

        orgrole = models.OrganisationRole.objects.create(
            organisation=org, role=role, for_all_users=False)

        profile = models.UserProfile.objects.fetch_for_user(user)
        self.assertEquals(
            len(list(profile.all_organisation_roles(portal))), 0)

        profile.roles.add(orgrole)

        self.assertEquals(
            len(list(profile.all_organisation_roles(portal))), 1)

    def test_they_are_not_both_returned(self):
        portal = factories.PortalF.create()
        user = factories.UserF.create(username='newuser')
        org = factories.OrganisationF.create()
        role = factories.RoleF.create(portal=portal)

        orgrole = models.OrganisationRole.objects.create(
            organisation=org, role=role, for_all_users=True)

        profile = models.UserProfile.objects.fetch_for_user(user)
        profile.organisations.add(org)
        profile.roles.add(orgrole)

        self.assertEquals(
            len(list(profile.all_organisation_roles(portal))), 1)

    def test_only_the_given_portal_is_returned(self):
        portal1 = factories.PortalF.create(name='portal1')
        portal2 = factories.PortalF.create(name='portal2')
        portal3 = factories.PortalF.create(name='portal3')

        role1 = factories.RoleF.create(name='role1', portal=portal1)
        role2 = factories.RoleF.create(name='role2', portal=portal2)
        role3 = factories.RoleF.create(name='role3', portal=portal2)  # Note: 2, not 3

        user = factories.UserF.create(username='newuser')
        org = factories.OrganisationF.create()

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

    def test_role_inheritance1(self):
        # User has role1 on portal1. He also has role2 on portal2 for the same
        # organisation because of role inheritance.

        portal1 = factories.PortalF.create(name='portal1')
        portal2 = factories.PortalF.create(name='portal2')
        role1 = factories.RoleF.create(name='role1', portal=portal1)
        role2 = factories.RoleF.create(name='role2', portal=portal2)
        org = factories.OrganisationF.create()
        user = factories.UserF.create(username='newuser')
        profile = models.UserProfile.objects.fetch_for_user(user)
        profile.organisations.add(org)

        # User has role1 because of for_all_users=True
        models.OrganisationRole.objects.create(
            organisation=org, role=role1, for_all_users=True)
        # But User wouldn't normally have this role
        org_role_2 = models.OrganisationRole.objects.create(
            organisation=org, role=role2, for_all_users=False)

        # See, he doesn't have any roles on portal2:
        self.assertEquals(
            len(list(profile.all_organisation_roles(portal2))), 0)

        # However, when the second role an inheriting role of the first (which
        # then becomes the second role's base role):
        role1.inheriting_roles.add(role2)

        # Then he does:
        self.assertEquals(
            profile.all_organisation_roles(portal2)[0],
            org_role_2)

    def test_role_inheritance2(self):
        # Same test as test_role_inheritance2, only "org_role_2" is attached
        # to a different organisation, so we don't get that role.

        portal1 = factories.PortalF.create(name='portal1')
        portal2 = factories.PortalF.create(name='portal2')
        role1 = factories.RoleF.create(name='role1', portal=portal1)
        role2 = factories.RoleF.create(name='role2', portal=portal2)
        org = factories.OrganisationF.create()
        second_org = factories.OrganisationF.create()
        user = factories.UserF.create(username='newuser')
        profile = models.UserProfile.objects.fetch_for_user(user)
        profile.organisations.add(org)

        # User has role1 because of for_all_users=True
        models.OrganisationRole.objects.create(
            organisation=org, role=role1, for_all_users=True)
        # But User wouldn't normally have this role
        models.OrganisationRole.objects.create(
            organisation=second_org, role=role2, for_all_users=False)
        # See, he doesn't have any roles on portal2:
        self.assertEquals(
            len(list(profile.all_organisation_roles(portal2))), 0)

        # Even when the second role is an inheriting role of the first we
        # don't get it as the organisations don't match.
        role1.inheriting_roles.add(role2)

        self.assertEquals(
            len(profile.all_organisation_roles(portal2)), 0)


class UnicodeMethodTestCase(TestCase):

    def test_unicode_portal(self):
        portal = factories.PortalF()
        self.assertEquals(type(portal.__unicode__()), unicode)

    def test_unicode_role(self):
        role = factories.RoleF()
        self.assertEquals(type(role.__unicode__()), unicode)

    def test_unicode_organisation(self):
        organisation = factories.OrganisationF()
        self.assertEquals(type(organisation.__unicode__()), unicode)

    def test_unicode_user_profile(self):
        user_profile = factories.UserProfileF()
        self.assertEquals(type(user_profile.__unicode__()), unicode)

    def test_unicode_invitation(self):
        invitation = factories.InvitationF()
        self.assertEquals(type(invitation.__unicode__()), unicode)
