# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.contrib import admin
from django.contrib import messages
from django.core.urlresolvers import reverse
from django.utils.translation import ugettext as _
from django.utils.translation import ugettext_lazy
from lizard_auth_server import models


class InvitationAdmin(admin.ModelAdmin):
    model = models.Invitation
    list_display = ['email', 'name', 'is_activated', 'user_profile_link',
                    'created_at', 'activated_on']
    search_fields = ['name', 'email']
    list_filter = ['is_activated']

    readonly_fields = ['created_at', 'shortcut_urls']
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
        if self.is_activated:
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
    list_filter = ['portals']
    # An additional list_filter on organisations is simply too long.

    filter_horizontal = ('portals', 'organisations')
    readonly_fields = [
        'created_at',
        'updated_at',
        'first_name',
        'last_name',
        'email'
    ]


class PortalAdmin(admin.ModelAdmin):
    model = models.Portal
    search_fields = ['name', 'visit_url', 'allowed_domain']
    list_display = ['name', 'visit_url', 'allowed_domain']


class TokenAdmin(admin.ModelAdmin):
    model = models.Token
    search_fields = ['portal__name', 'portal__visit_url', 'portal__allowed_domain']
    list_display = ['created', 'portal', 'user']


class OrganisationRoleAdmin(admin.ModelAdmin):
    ordering = ('role__portal', 'organisation', 'role')

admin.site.register(models.Portal, PortalAdmin)
admin.site.register(models.Token, TokenAdmin)
admin.site.register(models.Invitation, InvitationAdmin)
admin.site.register(models.UserProfile, UserProfileAdmin)
admin.site.register(models.Role)
admin.site.register(models.Organisation)
admin.site.register(models.OrganisationRole, OrganisationRoleAdmin)
