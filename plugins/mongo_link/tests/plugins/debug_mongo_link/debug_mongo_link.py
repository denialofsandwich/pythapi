#!/usr/bin/python3
# -*- coding: utf-8 -*-

import core.plugin_base
import core.casting

import datetime
import mongoengine
from .models import Person

plugin = core.plugin_base.PythapiPlugin("debug_mongo_link")
plugin.version = "1.0"
plugin.essential = False

plugin.depends = [
    {
        "name":"mongo_link",
        "required": True,
    }
]

plugin.config_defaults = {}

response_format_person = {
    "type_defaults": {
        Person: {
            "pre_format": lambda x, **kwargs: x.json
        }
    }
}

@core.plugin_base.event(plugin, 'core.load', {})
def load():
    global log
    log = core.plugin_base.log


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/person",
    "method": "GET",
    "request_content_type": 'application/json',
    "body_data": {},
    "response_format": response_format_person,
})
def get_person(body_data, url_params, **kwargs):
    return {
        "persons": list(Person.objects),
    }

@core.plugin_base.event(plugin, 'web.request', {
    "path": "/person",
    "method": "POST",
    "request_content_type": 'application/json',
    "body_data": {
        "child": {
            "name": {
                "type": str,
            },
            "age": {
                "type": int,
            },
        }
    },
    "response_format": {},
})
def new_person(body_data, url_params, **kwargs):
    return {
        "result": core.plugin_base.plugin_dict["mongo_link"].insert(Person, body_data)
    }


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/person",
    "method": "DELETE",
    "request_content_type": 'application/json',
    "body_data": {
        "child": {
            "name": {
                "type": str,
            },
        }
    },
    "response_format": {},
})
def delete_person(body_data, url_params, **kwargs):
    Person.objects.get(name=body_data['name']).delete()
    return {}
