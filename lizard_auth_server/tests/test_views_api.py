from django.test import TestCase
from lizard_auth_server import models
from lizard_auth_server import views_api
from lizard_auth_server.tests import factories


class TestGetOrganisationsView(TestCase):
    def setUp(self):
        self.view = views_api.GetOrganisationsView()

    def test_empty(self):
        result = self.view.get_organisations(None)
        self.assertEqual(result, {"organisations": []})

    def test_with_role(self):
        portal = factories.PortalF.create()
        role = factories.RoleF.create(portal=portal)
        organisation = factories.OrganisationF.create()
        models.OrganisationRole.objects.create(organisation=organisation, role=role)

        organisations = self.view.get_organisations(portal)["organisations"]

        self.assertEqual(len(organisations), 1)
        self.assertEqual(organisations[0]["unique_id"], organisation.unique_id)
