# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.contrib import admin
from django.contrib import messages
from django.core.urlresolvers import reverse
from django.db.models import Count
from django.utils.translation import ugettext as _
from django.utils.translation import ugettext_lazy
from lizard_auth_server import models


class InvitationAdmin(admin.ModelAdmin):
    model = models.Invitation
    list_display = ['email', 'name', 'is_activated', 'user_profile_link',
                    'created_at', 'activated_on']
    search_fields = ['name', 'email']
    list_filter = ['is_activated']

    readonly_fields = ['created_at', 'shortcut_urls', 'activation_key',
                       'activation_key_date', 'activated_on']
    actions = ['send_new_activation_email']

    def send_new_activation_email(self, request, queryset):
        for profile in queryset:
            if profile.is_activated:
                messages.error(
                    request,
                    'Invitation {} is already activated!'.format(profile),
                    fail_silently=False
                )
            else:
                profile.send_new_activation_email()
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
        if not obj.user:
            return
        if not obj.user.user_profile:
            return obj.user
        url = reverse('admin:lizard_auth_server_userprofile_change',
                      args=[obj.user.user_profile.id])
        return '<a href="{}">&rarr; {}</a>'.format(url, obj.user)
    user_profile_link.allow_tags = True
    user_profile_link.short_description = ugettext_lazy('user profile')


class UserProfileAdmin(admin.ModelAdmin):
    model = models.UserProfile
    list_display = ['username', 'full_name', 'email', 'created_at']
    search_fields = ['user__first_name', 'user__last_name', 'user__email']
    list_filter = ['portals', 'organisations']
    readonly_fields = ['updated_at', 'created_at']

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
                       'portals',
                       'organisations',
                       'roles',
                   ]}),
        (ugettext_lazy('Dates'), {
            'fields': ['created_at',
                       'updated_at',
                   ]}),
        (ugettext_lazy('Personal data'), {
            'fields': ['title',
                       'street',
                       'postal_code',
                       'town',
                       'phone_number',
                       'mobile_phone_number',
                   ]}),
    )


class PortalAdmin(admin.ModelAdmin):
    model = models.Portal
    search_fields = ['name', 'visit_url', 'allowed_domain']
    list_display = ['name', 'visit_url', 'allowed_domain',
                    'num_user_profiles', 'num_roles']
    fieldsets = (
        (None, {
            'fields': ['name',
                       'redirect_url',
                       'visit_url',
                       'allowed_domain',
                       ]}),
        (ugettext_lazy('Key and secret, not to be changed'), {
            'classes': ['collapse'],
            'fields': ['sso_secret',
                       'sso_key',
                       ]}),
    )

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
    num_user_profiles.short_description = ugettext_lazy('number of user profiles')
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


class RoleAdmin(admin.ModelAdmin):
    model = models.Role
    search_fields = ['code', 'name', 'portal__name', 'portal__visit_url',
                     'portal__allowed_domain',
                     'external_description', 'internal_description']
    list_display = ['code', 'portal', 'name', 'internal_description',
                    'num_organisation_roles']
    list_filter = [RelevantPortalFilter]

    def get_queryset(self, request):
        queryset = super(RoleAdmin, self).get_queryset(request)
        return queryset.annotate(
            organisation_roles_count=Count('organisation_roles', distinct=True))

    def num_organisation_roles(self, obj):
        count = obj.organisation_roles_count
        if not count:
            return ''
        url = reverse('admin:lizard_auth_server_organisationrole_changelist')
        url += '?role__id__exact={}'.format(obj.id)
        return '<a href="{}">&rarr; {}</a>'.format(url, count)
    num_organisation_roles.short_description = ugettext_lazy('number of organisation roles')
    num_organisation_roles.admin_order_field = 'organisation_roles_count'
    num_organisation_roles.allow_tags = True


class OrganisationAdmin(admin.ModelAdmin):
    model = models.Organisation
    search_fields = ['name']
    list_display = ['name', 'num_user_profiles', 'num_roles']

    def get_queryset(self, request):
        queryset = super(OrganisationAdmin, self).get_queryset(request)
        return queryset.annotate(user_profiles_count=Count('user_profiles'),
                                 roles_count=Count('roles', distinct=True))

    def num_user_profiles(self, obj):
        count = obj.user_profiles_count
        url = reverse('admin:lizard_auth_server_userprofile_changelist')
        url += '?organisations__id__exact={}'.format(obj.id)
        return '<a href="{}">&rarr; {}</a>'.format(url, count)
    num_user_profiles.short_description = ugettext_lazy('number of user profiles')
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
    search_fields = ['portal__name', 'portal__visit_url', 'portal__allowed_domain']
    list_display = ['created', 'portal', 'user']
    readonly_fields = ['request_token', 'auth_token']


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
    list_display = ['__unicode__', 'role', 'organisation']
    list_filter = ['role', RelevantOrganisationFilter]
    search_fields = ['organisation__name', 'role__name', 'role__portal__name']


admin.site.register(models.Portal, PortalAdmin)
admin.site.register(models.Token, TokenAdmin)
admin.site.register(models.Invitation, InvitationAdmin)
admin.site.register(models.UserProfile, UserProfileAdmin)
admin.site.register(models.Role, RoleAdmin)
admin.site.register(models.Organisation, OrganisationAdmin)
admin.site.register(models.OrganisationRole, OrganisationRoleAdmin)
