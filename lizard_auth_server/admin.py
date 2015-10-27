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
    list_display = ['__unicode__', 'user', 'email', 'is_activated']
    readonly_fields = ['created_at', 'shortcut_urls']
    actions = ['send_new_activation_email']
    search_fields = ['name', 'email']

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


class UserProfileAdmin(admin.ModelAdmin):
    model = models.UserProfile
    list_display = ['__unicode__', 'user']
    readonly_fields = [
        'created_at',
        'updated_at',
        'first_name',
        'last_name',
        'email'
    ]
    search_fields = ['user__first_name', 'user__last_name', 'user__email']
    filter_horizontal = ('portals', 'organisations')


class PortalAdmin(admin.ModelAdmin):
    model = models.Portal
#    form = PortalForm


class OrganisationRoleAdmin(admin.ModelAdmin):
    ordering = ('role__portal', 'organisation', 'role')

admin.site.register(models.Portal, PortalAdmin)
admin.site.register(models.Token)
admin.site.register(models.Invitation, InvitationAdmin)
admin.site.register(models.UserProfile, UserProfileAdmin)
admin.site.register(models.Role)
admin.site.register(models.Organisation)
admin.site.register(models.OrganisationRole, OrganisationRoleAdmin)
