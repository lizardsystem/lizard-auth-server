# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.utils import simplejson as json
from django.http import HttpResponse

def JsonResponse(data, already_serialized=False):
    if isinstance(data, dict):
        if not 'success' in data:
            if 'errors' in data:
                data['success'] = False
            else:
                data['success'] = True

    return HttpResponse(
        data if already_serialized else json.dumps(data),
        content_type='application/json'
    )

def JsonError(error_string):
    data = {
        'success': False,
        'errors': error_string,
    }
    return JsonResponse(data)
