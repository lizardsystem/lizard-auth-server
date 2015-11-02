from django.test import TestCase
from django.test.client import RequestFactory
from lizard_auth_server import admin
from lizard_auth_server import models
from lizard_auth_server.tests import factories
from django.contrib.admin.sites import AdminSite

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
