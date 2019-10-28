#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base
from . import header
from . import base

import mongoengine.base


# TODO: Dinge die ich brauche um weiterzumachen:
#   - restrict Keys in casting.py
#   - event priorisieren template
#   - mongo_link überarbeiten
#   -
#   - Dann:
#       - Install Events
#       - Klassen implementierung (User, Token, Role)
#       - Requests
#       - ruleset handling
#       - pre_exec Event
#       - Testing


@core.plugin_base.event(header.plugin, 'core.load')
def load():
    print([x.to_mongo().to_dict() for x in base.User.objects(name__contains='olga')])


@core.plugin_base.event(header.plugin, 'web.request', {
    "path": "/user",
    "method": "POST",
    "request_content_type": 'application/json',
    "body_data": {
        "child": {
            "name": {
                "type": str,
            },
            "password": {
                "type": str,
            },
            "ruleset": {
                "type": dict,
                "default": {}
            },
        }
    },
})
def new_person(body_data, url_params, **kwargs):
    return {
        "data": base.User(**body_data).save()  # TODO: IMPORTANT! Implement restrict Keys in casting.py
    }


@core.plugin_base.event(header.plugin, 'web.request', {
    "path": "/user/{user_name}",
    "method": "GET",
    "request_content_type": 'application/json',
    "path_params": {
        "child": {
            "user_name": {
                "type": str,
            },
        }
    },
#    "output_message_format": {
#        "type_defaults": {
#            mongoengine.base.datastructures.BaseDict: {
#                "type": dict,
#                "pre_format": lambda x, **k: dict(x)
#            },
#            mongoengine.base.datastructures.BaseList: {
#                "type": list,
#                "pre_format": lambda x, **k: list(x)
#            }
#        }
#    },
})
def new_person(path_params, **kwargs):
    return {
        "data": [x.to_mongo().to_dict() for x in base.User.objects(name__contains=path_params['user_name'])]
    }
