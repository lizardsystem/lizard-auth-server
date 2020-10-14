# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.http import HttpResponse

import json


def JsonResponse(data, already_serialized=False):
    if isinstance(data, dict):
        if "success" not in data:
            if "error" in data:
                data["success"] = False
            else:
                data["success"] = True

    return HttpResponse(
        data if already_serialized else json.dumps(data),
        content_type="application/json",
    )


def JsonError(error_string):
    data = {
        "success": False,
        "error": error_string,
    }
    return JsonResponse(data)
