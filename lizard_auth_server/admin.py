# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.contrib import admin
from django.contrib import messages
from django.core.urlresolvers import reverse
from django.db.models import Count
from django.utils.translation import ugettext as _
from django.utils.translation import ugettext_lazy
from lizard_auth_server import forms
from lizard_auth_server import models
from tls import request as tls_request


class InvitationAdmin(admin.ModelAdmin):
    model = models.Invitation
    list_display = ['email', 'name', 'is_activated', 'user_profile_link',
                    'created_at', 'activated_on']
    search_fields = ['name', 'email']
    list_filter = ['is_activated']
    list_select_related = ['user', 'user__user_profile']

    readonly_fields = ['created_at', 'activation_key',
                       'activation_key_date', 'activated_on',
                       'shortcut_urls']
    actions = ['send_new_activation_email']
    filter_horizontal = ['portals']

    def send_new_activation_email(self, request, queryset):
        for invitation in queryset:
            if invitation.is_activated:
                messages.error(
                    request,
                    'Invitation {} is already activated!'.format(invitation),
                    fail_silently=False
                )
            else:
                invitation.send_new_activation_email()
    send_new_activation_email.short_description = ugettext_lazy(
        'Resend the activation email, with a new key'
    )

    def shortcut_urls(self, obj):
        if obj.is_activated:
            return ''
        else:
            url = reverse(
                'lizard_auth_server.activate',
                kwargs={'activation_key': obj.activation_key}
            )
            return '<a href="{}">{}</a>'.format(url, _('Activate manually'))
    shortcut_urls.allow_tags = True
    shortcut_urls.short_description = ugettext_lazy('Shortcut URLs')

    def user_profile_link(self, obj):
        if not obj.user or not obj.user.user_profile:
            return
        url = reverse('admin:lizard_auth_server_userprofile_change',
                      args=[obj.user.user_profile.id])
        return '<a href="{}">&rarr; {}</a>'.format(url, obj.user)
    user_profile_link.allow_tags = True
    user_profile_link.short_description = ugettext_lazy('user profile')


class UserProfileAdmin(admin.ModelAdmin):
    model = models.UserProfile
    form = forms.UserProfileForm
    list_display = ['username', 'full_name', 'email', 'created_at']
    search_fields = ['user__first_name', 'user__last_name', 'user__email']
    list_filter = ['portals', 'organisations']
    readonly_fields = ['updated_at', 'created_at']
    list_select_related = ['user']

    filter_horizontal = ('portals', 'organisations', 'roles')
    readonly_fields = [
        'created_at',
        'updated_at',
        'first_name',
        'last_name',
        'email'
    ]
    fieldsets = (
        (None, {
            'fields': ['user',
                       'first_name',
                       'last_name',
                   ]}),
        (ugettext_lazy('V1 authorization'), {
            'fields': ['portals',
                       'organisations',
                       'roles',
                   ]}),
        (ugettext_lazy('Dates'), {
            'fields': ['created_at',
                       'updated_at',
                   ]}),
    )


class RelevantPortalFilter(admin.SimpleListFilter):
    title = _('portal')
    parameter_name = 'portal__id__exact'

    def lookups(self, request, model_admin):
        return models.Portal.objects.filter(
            roles__isnull=False).distinct().values_list(
            'id', 'name')

    def queryset(self, request, queryset):
        if not self.value():
            return queryset
        return queryset.filter(portal=self.value())


class RoleInline(admin.TabularInline):
    model = models.Role
    fields = ['code', 'name', 'internal_description', 'external_description',
              'num_inheriting_roles']
    readonly_fields = ['internal_description', 'external_description',
                       'num_inheriting_roles']
    # TODO: add show_change_link when we move to django 1.8.
    extra = 1

    def get_queryset(self, request):
        # Direct copy/paste from RoleAdmin (apart from the different 'super').
        queryset = super(RoleInline, self).get_queryset(request)
        return queryset.annotate(
            inheriting_roles_count=Count('inheriting_roles', distinct=True))

    def num_inheriting_roles(self, obj):
        # Direct copy/paste from RoleAdmin
        count = obj.inheriting_roles_count
        if not count:
            return ''
        url = reverse('admin:lizard_auth_server_role_changelist')
        url += '?base_role={}'.format(obj.id)
        return '<a href="{}">&rarr; {}</a>'.format(url, count)
    num_inheriting_roles.short_description = ugettext_lazy(
        'number of inheriting roles')
    num_inheriting_roles.admin_order_field = 'inheriting_roles_count'
    num_inheriting_roles.allow_tags = True


class OrganisationRoleInline(admin.TabularInline):
    model = models.OrganisationRole
    extra = 1


class RelevantBaseRoleFilter(admin.SimpleListFilter):
    title = _('base role')
    parameter_name = 'base_role'

    def lookups(self, request, model_admin):
        return models.Role.objects.exclude(
            inheriting_roles__isnull=True).values_list(
            'id', 'name')

    def queryset(self, request, queryset):
        if not self.value():
            return queryset
        return queryset.filter(base_roles=self.value())


class RoleAdmin(admin.ModelAdmin):
    model = models.Role
    search_fields = ['code', 'name', 'portal__name', 'portal__visit_url',
                     'portal__allowed_domain',
                     'external_description', 'internal_description']
    list_display = ['code', 'portal', 'name', 'internal_description',
                    'num_organisation_roles', 'num_inheriting_roles']
    list_filter = [RelevantPortalFilter, RelevantBaseRoleFilter]
    readonly_fields = ['unique_id']
    filter_horizontal = ['inheriting_roles']

    # inlines = [OrganisationRoleInline]
    # ^^^ This is easy to enable, but I [reinout] found it unclear how to use
    # it. Better to only have this inline on Organisation only.

    def get_queryset(self, request):
        queryset = super(RoleAdmin, self).get_queryset(request)
        return queryset.annotate(
            organisation_roles_count=Count('organisation_roles',
                                           distinct=True),
            inheriting_roles_count=Count('inheriting_roles',
                                         distinct=True))

    def num_organisation_roles(self, obj):
        count = obj.organisation_roles_count
        if not count:
            return ''
        url = reverse('admin:lizard_auth_server_organisationrole_changelist')
        url += '?role__id__exact={}'.format(obj.id)
        return '<a href="{}">&rarr; {}</a>'.format(url, count)
    num_organisation_roles.short_description = ugettext_lazy(
        'number of organisation roles')
    num_organisation_roles.admin_order_field = 'organisation_roles_count'
    num_organisation_roles.allow_tags = True

    def num_inheriting_roles(self, obj):
        count = obj.inheriting_roles_count
        if not count:
            return ''
        url = reverse('admin:lizard_auth_server_role_changelist')
        url += '?base_role={}'.format(obj.id)
        return '<a href="{}">&rarr; {}</a>'.format(url, count)
    num_inheriting_roles.short_description = ugettext_lazy(
        'number of inheriting roles')
    num_inheriting_roles.admin_order_field = 'inheriting_roles_count'
    num_inheriting_roles.allow_tags = True


class PortalAdmin(admin.ModelAdmin):
    model = models.Portal
    search_fields = ['name', 'visit_url', 'allowed_domain']
    list_display = ['name', 'visit_url', 'allowed_domain',
                    'num_user_profiles', 'num_roles']
    readonly_fields = ['sso_secret', 'sso_key', 'v2_config']
    inlines = [RoleInline]

    def get_queryset(self, request):
        queryset = super(PortalAdmin, self).get_queryset(request)
        return queryset.annotate(
            user_profiles_count=Count('user_profiles', distinct=True),
            roles_count=Count('roles', distinct=True))

    def num_user_profiles(self, obj):
        count = obj.user_profiles_count
        url = reverse('admin:lizard_auth_server_userprofile_changelist')
        url += '?portals__id__exact={}'.format(obj.id)
        return '<a href="{}">&rarr; {}</a>'.format(url, count)
    num_user_profiles.short_description = ugettext_lazy(
        'number of user profiles')
    num_user_profiles.admin_order_field = 'user_profiles_count'
    num_user_profiles.allow_tags = True

    def num_roles(self, obj):
        count = obj.roles_count
        url = reverse('admin:lizard_auth_server_role_changelist')
        url += '?portal__id__exact={}'.format(obj.id)
        return '<a href="{}">&rarr; {}</a>'.format(url, count)
    num_roles.short_description = ugettext_lazy('number of roles')
    num_roles.admin_order_field = 'roles_count'
    num_roles.allow_tags = True

    def v2_config(self, obj):
        config_lines = [
            "SSO_ENABLED = True",
            "SSO_USE_V2_login = True",
            "SSO_SERVER_API_START_URL = '{}'".format(
                tls_request.build_absolute_uri(
                    reverse('lizard_auth_server.api_v2.start'))),
            "SSO_KEY = '{}'".format(obj.sso_key),
            "SSO_SECRET = '{}'".format(obj.sso_secret),
            ]
        return '<pre>{}</pre>'.format('\n'.join(config_lines))
    v2_config.short_description = ugettext_lazy('settings for the v2 API')
    v2_config.allow_tags = True


class OrganisationAdmin(admin.ModelAdmin):
    model = models.Organisation
    search_fields = ['name']
    list_display = ['name', 'num_user_profiles', 'num_roles']
    readonly_fields = ['unique_id']
    inlines = [OrganisationRoleInline]

    def get_queryset(self, request):
        queryset = super(OrganisationAdmin, self).get_queryset(request)
        return queryset.annotate(
            user_profiles_count=Count('user_profiles', distinct=True),
            roles_count=Count('roles', distinct=True))

    def num_user_profiles(self, obj):
        count = obj.user_profiles_count
        url = reverse('admin:lizard_auth_server_userprofile_changelist')
        url += '?organisations__id__exact={}'.format(obj.id)
        return '<a href="{}">&rarr; {}</a>'.format(url, count)
    num_user_profiles.short_description = ugettext_lazy(
        'number of user profiles')
    num_user_profiles.admin_order_field = 'user_profiles_count'
    num_user_profiles.allow_tags = True

    def num_roles(self, obj):
        count = obj.roles_count
        if not count:
            return ''
        url = reverse('admin:lizard_auth_server_organisationrole_changelist')
        url += '?organisation__id__exact={}'.format(obj.id)
        return '<a href="{}">&rarr; {}</a>'.format(url, count)
    num_roles.short_description = ugettext_lazy('number of roles')
    num_roles.admin_order_field = 'roles_count'
    num_roles.allow_tags = True


class TokenAdmin(admin.ModelAdmin):
    model = models.Token
    search_fields = ['portal__name', 'portal__visit_url',
                     'portal__allowed_domain']
    list_display = ['created', 'portal', 'user']
    readonly_fields = ['created', 'request_token', 'auth_token']


class RelevantOrganisationFilter(admin.SimpleListFilter):
    title = _('organisation')
    parameter_name = 'organisation__id__exact'

    def lookups(self, request, model_admin):
        return models.Organisation.objects.filter(
            organisation_roles__isnull=False).distinct().values_list(
            'id', 'name')

    def queryset(self, request, queryset):
        if not self.value():
            return queryset
        return queryset.filter(organisation=self.value())


class OrganisationRoleAdmin(admin.ModelAdmin):
    model = models.OrganisationRole
    ordering = ('role__portal', 'organisation', 'role')
    list_display = ['__str__', 'role', 'organisation']
    list_filter = ['role', RelevantOrganisationFilter]
    search_fields = ['organisation__name', 'role__name', 'role__portal__name']


admin.site.register(models.Portal, PortalAdmin)
admin.site.register(models.Token, TokenAdmin)
admin.site.register(models.Invitation, InvitationAdmin)
admin.site.register(models.UserProfile, UserProfileAdmin)
admin.site.register(models.Role, RoleAdmin)
admin.site.register(models.Organisation, OrganisationAdmin)
admin.site.register(models.OrganisationRole, OrganisationRoleAdmin)
