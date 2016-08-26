from django.contrib.admin.sites import AdminSite
from django.contrib.auth.models import User
from django.contrib.messages.storage.fallback import FallbackStorage
from django.core.urlresolvers import reverse
from django.test import Client
from django.test import TestCase
from django.test.client import RequestFactory
from lizard_auth_server import admin
from lizard_auth_server import models
from lizard_auth_server.tests import factories

import mock


class TestSearchFields(TestCase):

    def test_for_valid_search_fields(self):
        # It is easy to add a foreignkey in a search field instead of a
        # stringfield on the class the foreign key points to.
        for model_admin_class in [
                admin.PortalAdmin,
                admin.TokenAdmin,
                admin.InvitationAdmin,
                admin.UserProfileAdmin,
                admin.RoleAdmin,
                admin.OrganisationAdmin,
                admin.OrganisationRoleAdmin]:
            model_class = model_admin_class.model
            print("Testing search fields for %s" % model_class)
            for fieldname in model_admin_class.search_fields:
                query = '%s__icontains' % fieldname
                print("Testing with %s" % query)
                kwargs = {query: 'reinout'}
                # We have no content, so the number of results if we search on
                # something should be zero. The only thing that matters is
                # that we get no 'cannot search on foreignkey' error.
                self.assertEquals(
                    model_class.objects.filter(**kwargs).count(),
                    0)


class TestInvitationAdmin(TestCase):

    def setUp(self):
        self.invitation = factories.InvitationF()
        self.request_factory = RequestFactory()
        self.some_request = self.request_factory.get('/admin/')
        site = AdminSite()
        self.admin_instance = admin.InvitationAdmin(models.Invitation, site)

    @mock.patch.object(models.Invitation, 'send_new_activation_email')
    def test_send_new_activation_email1(self, patched_method):
        # Patch method actually sends the activation email.
        queryset = models.Invitation.objects.filter(id=self.invitation.id)
        self.admin_instance.send_new_activation_email(self.some_request, queryset)
        self.assertTrue(patched_method.called)

    @mock.patch('django.contrib.messages.error')
    def test_send_new_activation_email2(self, patched_method):
        # Patched method is the error message printing "We are already activated".
        self.invitation.is_activated = True
        self.invitation.save()
        queryset = models.Invitation.objects.filter(id=self.invitation.id)
        self.admin_instance.send_new_activation_email(self.some_request, queryset)
        self.assertTrue(patched_method.called)

    def test_shortcut_urls1(self):
        # By default, show a shortcut url for manual activation.
        self.assertTrue('href' in self.admin_instance.shortcut_urls(self.invitation))

    def test_shortcut_urls2(self):
        # If activated, no shortcut url for manual activation.
        self.invitation.is_activated = True
        self.assertEquals(self.admin_instance.shortcut_urls(self.invitation), '')

    def test_user_profile_link1(self):
        # No user profle? No handy link.
        self.assertEquals(self.admin_instance.user_profile_link(self.invitation),
                          None)

    def test_user_profile_link2(self):
        user_profile = factories.UserProfileF()
        self.invitation.user = user_profile.user
        # User profle? Link to the user profile.
        self.assertTrue(
            'href' in self.admin_instance.user_profile_link(self.invitation))


class TestOrganisationsMigrationAdmin(TestCase):

    def setUp(self):
        # Three users
        self.user1 = factories.UserF()
        self.user2 = factories.UserF()
        # Old organisation with two users.
        self.organisation = factories.OrganisationF()
        self.user1.user_profile.organisations.add(self.organisation)
        self.user2.user_profile.organisations.add(self.organisation)

        # Rest of the setup.
        self.request_factory = RequestFactory()
        self.some_request = self.request_factory.get('/admin/')
        site = AdminSite()
        self.admin_instance = admin.OrganisationAdmin(models.Organisation, site)

        # RequestFactory doesn't support middleware, see
        # http://stackoverflow.com/a/12011907/27401 for below hack.
        self.some_request.session = 'session'
        self.messages = FallbackStorage(self.some_request)
        self.some_request._messages = self.messages

    def test_test_setup(self):
        self.assertEquals(models.UserProfile.objects.all().count(), 2)
        self.assertEquals(models.Profile.objects.all().count(), 2)
        self.assertEquals(self.organisation.user_profiles.all().count(), 2)
        self.assertEquals(self.user1.profile,
                          self.user1.user_profile.user.profile)

    def test_simple_copy_adds_a_company(self):
        queryset = models.Organisation.objects.filter(id=self.organisation.id)
        self.admin_instance.copy_as_company(self.some_request, queryset)
        self.assertEquals(models.Company.objects.all().count(), 1)

    def test_simple_copy_also_copies_users(self):
        queryset = models.Organisation.objects.filter(id=self.organisation.id)
        self.admin_instance.copy_as_company(self.some_request, queryset)
        created_company = models.Company.objects.filter(
            name=self.organisation.name)[0]
        self.assertEquals(created_company.members.all().count(), 2)

    def test_existing_membership_stays_unchanged(self):
        some_existing_company = factories.CompanyF()
        self.user1.profile.company = some_existing_company
        self.user1.profile.save()

        queryset = models.Organisation.objects.filter(id=self.organisation.id)
        self.admin_instance.copy_as_company(self.some_request, queryset)
        created_company = models.Company.objects.filter(
            name=self.organisation.name)[0]
        self.assertEquals(some_existing_company.members.all().count(), 1)
        self.assertEquals(created_company.members.all().count(), 1)

    def test_member_elswhere_means_guest_membership(self):
        some_existing_company = factories.CompanyF()
        self.user1.profile.company = some_existing_company
        self.user1.profile.save()

        queryset = models.Organisation.objects.filter(id=self.organisation.id)
        self.admin_instance.copy_as_company(self.some_request, queryset)
        created_company = models.Company.objects.filter(
            name=self.organisation.name)[0]
        self.assertEquals(created_company.guests.all().count(), 1)

    def test_refuse_already_migrated_organisations(self):
        self.organisation.already_migrated = True
        self.organisation.save()
        queryset = models.Organisation.objects.filter(id=self.organisation.id)
        self.admin_instance.copy_as_company(self.some_request, queryset)
        self.assertEquals(models.Company.objects.all().count(), 0)

    def test_copy_sets_migration_checkbox(self):
        queryset = models.Organisation.objects.filter(id=self.organisation.id)
        self.admin_instance.copy_as_company(self.some_request, queryset)
        organisation = models.Organisation.objects.get(id=self.organisation.id)
        self.assertTrue(organisation.already_migrated)


class TestProfileAdmin(TestCase):

    def setUp(self):
        # Basic setup.
        self.request_factory = RequestFactory()
        self.some_request = self.request_factory.get('/admin/')
        site = AdminSite()
        self.admin_instance = admin.ProfileAdmin(models.Profile, site)

        # RequestFactory doesn't support middleware, see
        # http://stackoverflow.com/a/12011907/27401 for below hack.
        self.some_request.session = 'session'
        self.messages = FallbackStorage(self.some_request)
        self.some_request._messages = self.messages

    def test_convert_to_guest(self):
        company = factories.CompanyF()
        user = factories.UserF()
        user.profile.company = company
        user.profile.save()
        queryset = models.Profile.objects.filter(id=user.profile.id)
        self.admin_instance.convert_to_guest(self.some_request, queryset)

        user.profile.refresh_from_db()
        company.refresh_from_db()
        self.assertIsNone(user.profile.company)
        self.assertIn(user.profile, company.guests.all())

    def test_convert_to_guest_without_company(self):
        user = factories.UserF()
        queryset = models.Profile.objects.filter(id=user.profile.id)
        self.admin_instance.convert_to_guest(self.some_request, queryset)
        user.profile.refresh_from_db()
        self.assertIsNone(user.profile.company)
        self.assertEquals(user.profile.companies_as_guest.count(), 0)


class TestSmokeAdminPages(TestCase):
    """Smoke tests with the basic test client

    The test calls the list page and the edit page for all models and simply
    checks if you get a '200 OK' status code back.
    """

    def setUp(self):
        User.objects.create_superuser('admin', 'a@a.nl', 'admin')
        self.client = Client()
        self.client.login(username='admin', password='admin')
        # Create a bunch of objects.
        self.user_profile = factories.UserProfileF()
        self.portal = factories.PortalF()
        self.role = factories.RoleF()
        self.token = factories.TokenF()
        self.organisation = factories.OrganisationF()
        self.invitation = factories.InvitationF()
        self.profile = factories.ProfileF()
        self.company = factories.CompanyF()
        self.site = factories.SiteF()

    # Part one: list pages.

    def _check_changelist_page_200(self, model_name):
        url = reverse('admin:lizard_auth_server_%s_changelist' % model_name)
        self.assertEquals(self.client.get(url).status_code, 200)

    def test_userprofile_list(self):
        self._check_changelist_page_200('userprofile')

    def test_portal_list(self):
        self._check_changelist_page_200('portal')

    def test_role_list(self):
        self._check_changelist_page_200('role')

    def test_token_list(self):
        self._check_changelist_page_200('token')

    def test_organisation_list(self):
        self._check_changelist_page_200('organisation')

    def test_invitation_list(self):
        self._check_changelist_page_200('invitation')

    def test_profile_list(self):
        self._check_changelist_page_200('profile')

    def test_company_list(self):
        self._check_changelist_page_200('company')

    def test_site_list(self):
        self._check_changelist_page_200('site')

    # Part one: edit pages.

    def _check_change_page_200(self, obj):
        model_name = obj._meta.model_name
        url = reverse('admin:lizard_auth_server_%s_change' % model_name,
                      args=[obj.id])
        self.assertEquals(self.client.get(url).status_code, 200)

    def test_userprofile_change_page(self):
        self._check_change_page_200(self.user_profile)

    def test_portal_change_page(self):
        self._check_change_page_200(self.portal)

    def test_role_change_page(self):
        self._check_change_page_200(self.role)

    def test_token_change_page(self):
        self._check_change_page_200(self.token)

    def test_organisation_change_page(self):
        self._check_change_page_200(self.organisation)

    def test_invitation_change_page(self):
        self._check_change_page_200(self.invitation)

    def test_profile_change_page(self):
        self._check_change_page_200(self.profile)

    def test_company_change_page(self):
        self._check_change_page_200(self.company)

    def test_site_change_page(self):
        self._check_change_page_200(self.site)
