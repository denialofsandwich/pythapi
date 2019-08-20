#!/usr/bin/python3
# -*- coding: utf-8 -*-

import core.plugin_base
import re

plugin = core.plugin_base.PythapiPlugin("web")
plugin.version = "1.0"
plugin.essential = False

plugin.info['f_name'] = {
    'EN': 'Webserver'
}

plugin.info['f_description'] = {
    'EN': 'Provides a HTTP-API-interface.',
    'DE': 'Stellt ein HTTP API-Interface bereit..'
}

plugin.depends = []

plugin.config_defaults = {
    plugin.name: {
        "http_binds": {
            "type": list,
            "default": [["0.0.0.0", "8123"]],
            "children": {
                "type": list,
                "delimiter": ':',
                "children": {
                    "type": str
                },
            }
        },
        "https_binds": {
            "type": list,
            "default": [],
            "children": {
                "type": list,
                "delimiter": ':',
                "children": {
                    "type": str
                },
            },
        },
        "ssl_cert_file": {
            "type": str,
            "default": ""
        },
        "ssl_key_file": {
            "type": str,
            "default": ""
        },
        "additional_headers": {
            "type": list,
            "default": [],
            "children": {
                "type": list,
                "delimiter": ':',
                "children": {
                    "type": str
                },
            },
        },
    },
}


def _post_event_data_formatter(val, t, **kwargs):
    if "path" in val:
        val['regex'] = '^/' + kwargs['d_plugin_name'] + val['path'].replace('*', '([^/]*)') + '$'

    if "regex" in val:
        val["c_regex"] = re.compile(val["regex"])

    return val


web_request_data_skeleton = {
    "type": dict,
    "post_format": _post_event_data_formatter,
    "child": {
        "method": {
            "type": str,
            "default": "GET",
        },
        "regex": {
            "type": str,
        },
        "path": {
            "type": str,
        }
    },
}

request_list = {
    'GET': [],
    'POST': [],
    'PUT': [],
    'DELETE': [],
    'OPTIONS': [],
}
