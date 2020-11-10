# -*- coding: utf-8 -*-
# Note: contains monkeypatch
from django.utils.translation import ugettext_lazy as _

import oidc_provider.lib.claims


def userinfo(claims, user):
    # Populate claims dict.
    # Scope 'profile'
    claims["name"] = "{0} {1}".format(user.first_name, user.last_name)
    claims["given_name"] = user.first_name
    claims["family_name"] = user.last_name
    claims["preferred_username"] = user.username
    # Scope 'email'
    claims["email"] = user.email

    return claims


OriginalStandardScopeClaims = oidc_provider.lib.claims.StandardScopeClaims


class StandardScopeClaims(OriginalStandardScopeClaims):
    # Monkeypatched class: we're stripping out claims we won't use.

    info_profile = (
        _("Basic profile"),
        _("Your name and username."),
    )

    def scope_profile(self):
        dic = {
            "name": self.userinfo.get("name"),
            "given_name": self.userinfo.get("given_name")
            or getattr(self.user, "first_name", None),
            "family_name": self.userinfo.get("family_name")
            or getattr(self.user, "last_name", None),
            # 'middle_name': self.userinfo.get('middle_name'),
            # 'nickname': self.userinfo.get('nickname') or getattr(self.user, 'username', None),
            "preferred_username": self.userinfo.get("preferred_username"),
            # 'profile': self.userinfo.get('profile'),
            # 'picture': self.userinfo.get('picture'),
            # 'website': self.userinfo.get('website'),
            # 'gender': self.userinfo.get('gender'),
            # 'birthdate': self.userinfo.get('birthdate'),
            # 'zoneinfo': self.userinfo.get('zoneinfo'),
            # 'locale': self.userinfo.get('locale'),
            # 'updated_at': self.userinfo.get('updated_at'),
        }

        return dic

    info_email = (
        _("Email"),
        _("Your email address."),
    )

    def scope_email(self):
        dic = {
            "email": self.userinfo.get("email") or getattr(self.user, "email", None),
            # 'email_verified': self.userinfo.get('email_verified'),
        }

        return dic

    info_phone = (
        _("Phone number"),
        _("Unused. We're not storing your phone number."),
    )

    def scope_phone(self):
        dic = {
            # 'phone_number': self.userinfo.get('phone_number'),
            # 'phone_number_verified': self.userinfo.get('phone_number_verified'),
        }

        return dic

    info_address = (
        _("Address information"),
        _("Unused. We're not storing your address."),
    )

    def scope_address(self):
        dic = {
            "address": {
                # 'formatted': self.userinfo.get('address', {}).get('formatted'),
                # 'street_address': self.userinfo.get('address', {}).get('street_address'),
                # 'locality': self.userinfo.get('address', {}).get('locality'),
                # 'region': self.userinfo.get('address', {}).get('region'),
                # 'postal_code': self.userinfo.get('address', {}).get('postal_code'),
                # 'country': self.userinfo.get('address', {}).get('country'),
            }
        }

        return dic


# Monkey patch
oidc_provider.lib.claims.StandardScopeClaims = StandardScopeClaims
