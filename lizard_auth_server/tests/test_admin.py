from django.test import TestCase
from lizard_auth_server import admin


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
