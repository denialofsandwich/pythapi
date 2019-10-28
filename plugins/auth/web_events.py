#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base
from . import header
from . import base

import mongoengine


@core.plugin_base.event(header.plugin, 'core.load')
def load():
    print([x.json for x in base.User.objects(name__contains='juliet')])


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
        }
    },
    "response_format": {},
})
def new_person(body_data, url_params, **kwargs):
    return {
        "data": base.User(name=body_data['name'], password=body_data['password']).save()
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
    "response_format": {},
})
def new_person(path_params, **kwargs):
    return {
        "data": [x.json for x in base.User.objects(name__contains=path_params['user_name'])]
    }
