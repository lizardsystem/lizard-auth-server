# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin
from django import forms
from django.utils.translation import ugettext_lazy, ugettext as _
from django.core.urlresolvers import reverse
from django.contrib import messages

from lizard_auth_server import models


#class PortalForm(forms.ModelForm):
#    sso_secret = forms.CharField(initial='test')
#
#    class Meta:
#        model = models.Portal

class InvitationAdmin(admin.ModelAdmin):
    model = models.Invitation
    list_display = ['__unicode__', 'profile', 'email', 'is_activated']
    readonly_fields = ['created_at', 'shortcut_urls']
    actions = ['send_new_activation_email']
    search_fields = ['name', 'email']

    def send_new_activation_email(self, request, queryset):
        for profile in queryset:
            if profile.is_activated:
                messages.error(request, 'Invitation {} is already activated!'.format(profile), fail_silently=False)
            else:
                profile.send_new_activation_email()
    send_new_activation_email.short_description = ugettext_lazy('Resend the activation email, with a new key')

    def shortcut_urls(self, obj):
        url = reverse('lizard_auth_server.activate', kwargs={'activation_key': obj.activation_key})
        return '<a href="{}">{}</a>'.format(url, _('Activate manually'))
    shortcut_urls.allow_tags = True
    shortcut_urls.short_description = ugettext_lazy('Shortcut URLs')

class UserProfileAdmin(admin.ModelAdmin):
    model = models.UserProfile
    list_display = ['__unicode__', 'user']
    readonly_fields = ['created_at', 'updated_at', 'first_name', 'last_name', 'email']
    search_fields = ['user__first_name', 'user__last_name', 'user__email']

class PortalAdmin(admin.ModelAdmin):
    model = models.Portal
#    form = PortalForm

admin.site.register(models.Portal, PortalAdmin)
admin.site.register(models.Token)
admin.site.register(models.Invitation, InvitationAdmin)
admin.site.register(models.UserProfile, UserProfileAdmin)
