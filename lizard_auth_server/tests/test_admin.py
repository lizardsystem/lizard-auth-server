from django.contrib.admin.sites import AdminSite
from django.contrib.auth.models import User
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


class TestSmokeAdminPages(TestCase):

    def setUp(self):
        User.objects.create_superuser('admin', 'a@a.nl', 'admin')
        self.client = Client()
        self.client.login(username='admin', password='admin')
        # Create a bunch of objects.
        factories.UserProfileF()
        factories.PortalF()
        factories.RoleF()
        factories.TokenF()
        factories.OrganisationF()
        factories.InvitationF()

    def check_changelist_page_200(self, model_name):
        url = reverse('admin:lizard_auth_server_%s_changelist' % model_name)
        self.assertEquals(self.client.get(url).status_code, 200)

    def test_userprofile_list(self):
        self.check_changelist_page_200('userprofile')

    def test_portal_list(self):
        self.check_changelist_page_200('portal')

    def test_role_list(self):
        self.check_changelist_page_200('role')

    def test_token_list(self):
        self.check_changelist_page_200('token')

    def test_organisation_list(self):
        self.check_changelist_page_200('organisation')

    def test_invitation_list(self):
        self.check_changelist_page_200('invitation')
