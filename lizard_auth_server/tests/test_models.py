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
        self.assertEqual(profile.organisation, None)

    def test_without_setup_all_organisation_roles_empty(self):
        portal = factories.PortalF.create()
        profile = models.UserProfile()
        self.assertEqual(len(list(profile.all_organisation_roles(portal))), 0)

    def test_role_for_all_members_is_returned(self):
        portal = factories.PortalF.create()
        user = factories.UserF.create(username="newuser")
        org = factories.OrganisationF.create()
        role = factories.RoleF.create(portal=portal)

        models.OrganisationRole.objects.create(
            organisation=org, role=role, for_all_users=True
        )

        profile = models.UserProfile.objects.fetch_for_user(user)
        profile.organisations.add(org)

        self.assertEqual(len(list(profile.all_organisation_roles(portal))), 1)

    def test_role_for_user_is_returned(self):
        portal = factories.PortalF.create()
        user = factories.UserF.create(username="newuser2")
        org = factories.OrganisationF.create()
        role = factories.RoleF.create(portal=portal)

        orgrole = models.OrganisationRole.objects.create(
            organisation=org, role=role, for_all_users=False
        )

        profile = models.UserProfile.objects.fetch_for_user(user)
        self.assertEqual(len(list(profile.all_organisation_roles(portal))), 0)

        profile.roles.add(orgrole)

        self.assertEqual(len(list(profile.all_organisation_roles(portal))), 1)

    def test_they_are_not_both_returned(self):
        portal = factories.PortalF.create()
        user = factories.UserF.create(username="newuser")
        org = factories.OrganisationF.create()
        role = factories.RoleF.create(portal=portal)

        orgrole = models.OrganisationRole.objects.create(
            organisation=org, role=role, for_all_users=True
        )

        profile = models.UserProfile.objects.fetch_for_user(user)
        profile.organisations.add(org)
        profile.roles.add(orgrole)

        self.assertEqual(len(list(profile.all_organisation_roles(portal))), 1)

    def test_only_the_given_portal_is_returned(self):
        portal1 = factories.PortalF.create(name="portal1")
        portal2 = factories.PortalF.create(name="portal2")
        portal3 = factories.PortalF.create(name="portal3")

        role1 = factories.RoleF.create(name="role1", portal=portal1)
        role2 = factories.RoleF.create(name="role2", portal=portal2)
        role3 = factories.RoleF.create(name="role3", portal=portal2)
        # ^^^ Note: portal 2, not 3!

        user = factories.UserF.create(username="newuser")
        org = factories.OrganisationF.create()

        orgrole1 = models.OrganisationRole.objects.create(
            organisation=org, role=role1, for_all_users=True
        )
        orgrole2 = models.OrganisationRole.objects.create(
            organisation=org, role=role2, for_all_users=True
        )
        orgrole3 = models.OrganisationRole.objects.create(
            organisation=org, role=role3, for_all_users=True
        )

        profile = models.UserProfile.objects.fetch_for_user(user)
        profile.organisations.add(org)

        profile.roles.add(orgrole1)
        profile.roles.add(orgrole2)
        profile.roles.add(orgrole3)

        self.assertEqual(len(list(profile.all_organisation_roles(portal1))), 1)
        self.assertEqual(len(list(profile.all_organisation_roles(portal2))), 2)
        self.assertEqual(len(list(profile.all_organisation_roles(portal3))), 0)

    def test_role_inheritance1(self):
        # User has role1 on portal1. He also has role2 on portal2 for the same
        # organisation because of role inheritance.

        portal1 = factories.PortalF.create(name="portal1")
        portal2 = factories.PortalF.create(name="portal2")
        role1 = factories.RoleF.create(name="role1", portal=portal1)
        role2 = factories.RoleF.create(name="role2", portal=portal2)
        org = factories.OrganisationF.create()
        user = factories.UserF.create(username="newuser")
        profile = models.UserProfile.objects.fetch_for_user(user)
        profile.organisations.add(org)

        # User has role1 because of for_all_users=True
        models.OrganisationRole.objects.create(
            organisation=org, role=role1, for_all_users=True
        )
        # But User wouldn't normally have this role
        org_role_2 = models.OrganisationRole.objects.create(
            organisation=org, role=role2, for_all_users=False
        )

        # See, he doesn't have any roles on portal2:
        self.assertEqual(len(list(profile.all_organisation_roles(portal2))), 0)

        # However, when the second role an inheriting role of the first (which
        # then becomes the second role's base role):
        role1.inheriting_roles.add(role2)

        # Then he does:
        self.assertEqual(profile.all_organisation_roles(portal2)[0], org_role_2)

    def test_role_inheritance2(self):
        # Same test as test_role_inheritance2, only "org_role_2" is attached
        # to a different organisation, so we don't get that role.

        portal1 = factories.PortalF.create(name="portal1")
        portal2 = factories.PortalF.create(name="portal2")
        role1 = factories.RoleF.create(name="role1", portal=portal1)
        role2 = factories.RoleF.create(name="role2", portal=portal2)
        org = factories.OrganisationF.create()
        second_org = factories.OrganisationF.create()
        user = factories.UserF.create(username="newuser")
        profile = models.UserProfile.objects.fetch_for_user(user)
        profile.organisations.add(org)

        # User has role1 because of for_all_users=True
        models.OrganisationRole.objects.create(
            organisation=org, role=role1, for_all_users=True
        )
        # But User wouldn't normally have this role
        models.OrganisationRole.objects.create(
            organisation=second_org, role=role2, for_all_users=False
        )
        # See, he doesn't have any roles on portal2:
        self.assertEqual(len(list(profile.all_organisation_roles(portal2))), 0)

        # Even when the second role is an inheriting role of the first we
        # don't get it as the organisations don't match.
        role1.inheriting_roles.add(role2)

        self.assertEqual(len(profile.all_organisation_roles(portal2)), 0)

    def test_3di_billing_not_allowed_for_all(self):
        threedi_portal = factories.PortalF.create(name="3Di")
        org = factories.OrganisationF.create()
        billing_role = factories.RoleF.create(portal=threedi_portal, code="billing")

        orgrole = models.OrganisationRole.objects.create(
            organisation=org, role=billing_role, for_all_users=True
        )

        self.assertRaises(ValidationError, orgrole.clean)

    def test_3di_billing_not_allowed_multiple_times(self):
        threedi_portal = factories.PortalF.create(name="3Di")
        user = factories.UserF.create(username="newuser2")
        profile = models.UserProfile.objects.fetch_for_user(user)
        org1 = factories.OrganisationF.create()
        org2 = factories.OrganisationF.create()
        billing_role = factories.RoleF.create(portal=threedi_portal, code="billing")
        profile.portals.add(threedi_portal)

        orgrole1 = models.OrganisationRole.objects.create(
            organisation=org1, role=billing_role, for_all_users=True
        )
        orgrole2 = models.OrganisationRole.objects.create(
            organisation=org2, role=billing_role, for_all_users=True
        )
        profile.roles = [orgrole1, orgrole2]
        profile_form = forms.UserProfileForm(model_to_dict(profile), instance=profile)
        self.assertFalse(profile_form.is_valid())

    def test_3di_billing_required(self):
        threedi_portal = factories.PortalF.create(name="3Di")
        user = factories.UserF.create(username="newuser2")
        profile = models.UserProfile.objects.fetch_for_user(user)
        profile.portals.add(threedi_portal)
        # No billing org role set!
        profile_form = forms.UserProfileForm(model_to_dict(profile), instance=profile)
        self.assertFalse(profile_form.is_valid())

    def test_3di_billing_only_applies_to_users_with_access(self):
        threedi_portal = factories.PortalF.create(name="3Di")
        user = factories.UserF.create(username="newuser2")
        profile = models.UserProfile.objects.fetch_for_user(user)
        org1 = factories.OrganisationF.create()
        org2 = factories.OrganisationF.create()
        billing_role = factories.RoleF.create(portal=threedi_portal, code="billing")
        # Explicitly missing: adding threedi_portal to profile.portals!

        orgrole1 = models.OrganisationRole.objects.create(
            organisation=org1, role=billing_role, for_all_users=True
        )
        orgrole2 = models.OrganisationRole.objects.create(
            organisation=org2, role=billing_role, for_all_users=True
        )
        profile.roles = [orgrole1, orgrole2]
        profile_form = forms.UserProfileForm(model_to_dict(profile), instance=profile)
        self.assertTrue(profile_form.is_valid())


class StrMethodTestCase(TestCase):
    def call_str(self, obj):
        self.assertEqual(type(obj.__str__()), str)

    def test_str_portal(self):
        """Smoke tests."""
        objs = [
            factories.PortalF(),
            factories.RoleF(),
            factories.OrganisationF(),
            factories.UserProfileF(),
            factories.InvitationF(),
        ]

        for o in objs:
            self.call_str(o)
