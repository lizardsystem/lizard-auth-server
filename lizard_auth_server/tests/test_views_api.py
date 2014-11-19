from django.test import TestCase

from . import test_models
from lizard_auth_server import models
from lizard_auth_server import views_api


class TestGetOrganisationsView(TestCase):
    def setUp(self):
        self.view = views_api.GetOrganisationsView()

    def test_empty(self):
        response = self.view.get_organisations(None)
        self.assertEquals(
            response,
            {
                'success': True,
                'organisations': []})

    def test_with_role(self):
        portal = test_models.PortalF.create()
        role = test_models.RoleF.create(portal=portal)
        organisation = test_models.OrganisationF.create()
        models.OrganisationRole.objects.create(
            organisation=organisation, role=role)

        organisations = self.view.get_organisations(portal)['organisations']

        self.assertEquals(len(organisations), 1)
        self.assertEquals(
            organisations[0]['unique_id'], organisation.unique_id)
