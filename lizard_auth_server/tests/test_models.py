from __future__ import unicode_literals

from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.forms.models import model_to_dict
from django.test import TestCase

from lizard_auth_server import forms
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

    def test_3di_billing_not_allowed_for_all(self):
        threedi_portal = factories.PortalF.create(name='3Di')
        org = factories.OrganisationF.create()
        billing_role = factories.RoleF.create(portal=threedi_portal, code='billing')

        orgrole = models.OrganisationRole.objects.create(
            organisation=org, role=billing_role, for_all_users=True)

        self.assertRaises(ValidationError,
                          orgrole.clean)

    def test_3di_billing_not_allowed_multiple_times(self):
        threedi_portal = factories.PortalF.create(name='3Di')
        user = factories.UserF.create(username='newuser2')
        profile = models.UserProfile.objects.fetch_for_user(user)
        org1 = factories.OrganisationF.create()
        org2 = factories.OrganisationF.create()
        billing_role = factories.RoleF.create(portal=threedi_portal, code='billing')
        profile.portals.add(threedi_portal)

        orgrole1 = models.OrganisationRole.objects.create(
            organisation=org1, role=billing_role, for_all_users=True)
        orgrole2 = models.OrganisationRole.objects.create(
            organisation=org2, role=billing_role, for_all_users=True)
        profile.roles = [orgrole1, orgrole2]
        profile_form = forms.UserProfileForm(model_to_dict(profile),
                                             instance=profile)
        self.assertFalse(profile_form.is_valid())

    def test_3di_billing_required(self):
        threedi_portal = factories.PortalF.create(name='3Di')
        user = factories.UserF.create(username='newuser2')
        profile = models.UserProfile.objects.fetch_for_user(user)
        profile.portals.add(threedi_portal)
        # No billing org role set!
        profile_form = forms.UserProfileForm(model_to_dict(profile),
                                             instance=profile)
        self.assertFalse(profile_form.is_valid())

    def test_3di_billing_only_applies_to_users_with_access(self):
        threedi_portal = factories.PortalF.create(name='3Di')
        user = factories.UserF.create(username='newuser2')
        profile = models.UserProfile.objects.fetch_for_user(user)
        org1 = factories.OrganisationF.create()
        org2 = factories.OrganisationF.create()
        billing_role = factories.RoleF.create(portal=threedi_portal, code='billing')
        # Explicitly missing: adding threedi_portal to profile.portals!

        orgrole1 = models.OrganisationRole.objects.create(
            organisation=org1, role=billing_role, for_all_users=True)
        orgrole2 = models.OrganisationRole.objects.create(
            organisation=org2, role=billing_role, for_all_users=True)
        profile.roles = [orgrole1, orgrole2]
        profile_form = forms.UserProfileForm(model_to_dict(profile),
                                             instance=profile)
        self.assertTrue(profile_form.is_valid())


class StrMethodTestCase(TestCase):

    def call_str(self, obj):
        self.assertEquals(type(obj.__str__()), str)

    def test_str_portal(self):
        """Smoke tests."""
        objs = [
            factories.PortalF(),
            factories.RoleF(),
            factories.OrganisationF(),
            factories.UserProfileF(),
            factories.InvitationF(),
            factories.SiteF(),
            factories.CompanyF(),
            factories.ProfileF(),
        ]

        for o in objs:
            self.call_str(o)

    def test_profile_properties(self):
        """Simple property checks."""
        p = factories.ProfileF()
        p.username
        p.full_name
        p.first_name
        p.last_name
        p.email


class TestProfile(TestCase):

    def test_no_site_access(self):
        """Test that in the current (base) factory configuration the user
        profile has no access to the site.
        """
        company = factories.CompanyF()
        profile = factories.ProfileF()
        site = factories.SiteF.create(available_to=[company])
        self.assertFalse(profile.has_access(site))

    def test_site_access_as_employee(self):
        """Test that user has access when its company is in the available_to
        list of the site, i.e., employees have access to their company's sites.
        """
        company = factories.CompanyF()
        profile = factories.ProfileF()
        profile.company = company
        site = factories.SiteF.create(available_to=[company])
        self.assertTrue(profile.has_access(site))

    def test_site_access_as_guest(self):
        """Test that a guest at a company can access their sites."""
        profile = factories.ProfileF()
        company = factories.CompanyF.create(guests=[profile])
        site = factories.SiteF.create(available_to=[company])
        self.assertTrue(profile.has_access(site))


class TestPermissions(TestCase):
    @patch('lizard_auth_server.models.request')
    def test_user_cant_access_users(self, mock_class):
        """Normal users can't retrieve users."""
        profile = factories.ProfileF()
        mock_class.user = profile.user
        self.assertTrue(models.Profile.objects.all().count() == 0)

    @patch('lizard_auth_server.models.request')
    def test_superuser_can_get_users(self, mock_class):
        """Superusers can retrieve users."""
        profile = factories.ProfileF()
        mock_class.user = profile.user
        mock_class.user.is_superuser = True
        self.assertTrue(models.Profile.objects.all().count() > 0)

    @patch('lizard_auth_server.models.request')
    def test_admins_can_get_users(self, mock_class):
        """Admins can retrieve users from companies they manage."""
        profile = factories.ProfileF()
        mock_class.user = profile.user
        company = factories.CompanyF()
        profile.company = company
        profile.save()  # somehow this save is needed
        company.administrators.add(profile)
        self.assertTrue(models.Profile.objects.all().count() > 0)

    @patch('lizard_auth_server.models.request')
    def test_admins_cant_get_unmanaged(self, mock_class):
        """Admins can't retrieve users from companies they don't manage."""
        profile = factories.ProfileF()
        profile2 = factories.ProfileF()
        mock_class.user = profile.user
        company = factories.CompanyF()
        company2 = factories.CompanyF()
        profile.company = company
        profile.save()
        profile2.company = company2
        profile2.save()
        company.administrators.add(profile)
        # When only managing 1 company it can only get that company's users
        self.assertTrue(models.Profile.objects.all().count() == 1)
        self.assertTrue(profile in models.Profile.objects.all())

        # Now also manages company2, thus gets also those users
        company2.administrators.add(profile)
        self.assertTrue(models.Profile.objects.all().count() == 2)
        self.assertTrue(profile2 in models.Profile.objects.all())

    @patch('lizard_auth_server.models.request')
    def test_get_companies_normal(self, mock_class):
        """Normal users can only get their own company."""
        company = factories.CompanyF()
        profile = factories.ProfileF(company=None)
        profile.company = company
        profile.save()  # necessary evil for this to work
        mock_class.user = profile.user
        factories.CompanyF()  # Create an extra company in the db
        self.assertEqual(models.Company.objects.all().count(), 1)

    @patch('lizard_auth_server.models.request')
    def test_get_companies_admin(self, mock_class):
        """Admins can get companies they manage."""
        profile = factories.ProfileF(company=None)
        company = factories.CompanyF()
        profile.company = company
        profile.save()  # necessary evil for this to work
        mock_class.user = profile.user
        company2 = factories.CompanyF()
        company2.administrators.add(profile)
        self.assertEqual(models.Company.objects.all().count(), 2)
        self.assertTrue(company2 in models.Company.objects.all())

    @patch('lizard_auth_server.models.request')
    def test_get_companies_superuser(self, mock_class):
        """Superuser can get all."""
        profile = factories.ProfileF(company=None)
        profile.user.is_superuser = True
        company = factories.CompanyF()
        profile.company = company
        profile.save()  # necessary evil for this to work
        mock_class.user = profile.user
        factories.CompanyF()  # Create an extra company in the db
        self.assertEqual(models.Company.objects.all().count(), 2)
