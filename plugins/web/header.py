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

# TODO: Alle Keys nochmal doppelt und dreifach checken.

plugin.config_defaults = {
    plugin.name: {
        "binds": {
            "type": list,
            "delimiter": ';',
            "default": [
                {
                    "ip": "127.0.0.1",
                    "port": 8123,
                    "api_only": False,
                    "ssl": False,
                }
            ],
            "children": {
                "type": dict,
                "child": {
                    "ip": {
                        "type": str,
                        "default": "127.0.0.1",
                    },
                    "port": {
                        "type": int,
                        "default": 8123,
                    },
                    "api_only": {
                        "type": bool,
                        "default": False,
                    },
                    "ssl": {
                        "type": bool,
                        "default": False,
                    },
                    "cert_file": {
                        "type": str,
                        "verify": False,
                    },
                    "key_file": {
                        "type": str,
                        "verify": False,
                    },
                    "static_root": {
                        "type": str,
                        "verify": False,
                    },
                },
            }
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
            "pipe": [
                {
                    "type": dict,
                    "default": {}
                }
            ]
        },
    },
}


def _post_event_data_formatter(val, **kwargs):
    if "path" in val:
        val['regex'] = '^/' + kwargs['d_plugin_name'] + val['path'].replace('*', '([^/]*)') + '$'

    if "regex" in val:
        val["_c_regex"] = re.compile(val["regex"])

    return val


web_request_data_skeleton = {
    "type": dict,
    "post_format": _post_event_data_formatter,
    "child": {
        "name": {
            "type": str,
        },
        "method": {
            "type": str,
            "default": "GET",
        },
        "regex": {
            "type": str,
        },
        "path": {
            "type": str,
        },
        "request_content_type": {
            "type": str,
            "default": "application/json"
        },
        "content_type": {
            "type": str,
            "default": "application/json"
        },
        'path_params': {
            'type': dict,
            'default': {},
        },
        'url_params': {
            'type': dict,
            'default': {},
        },
        'post_body': {
            'type': dict,
            'default': {},
        },
        'response_format': {
            'type': dict,
            'default': {},
        },
    },
}
plugin.web_request_data_skeleton = web_request_data_skeleton

web_socket_data_skeleton = {
    "type": dict,
    "post_format": _post_event_data_formatter,
    "child": {
        "name": {
            "type": str,
        },
        "method": {
            "type": str,
            "default": "GET",
        },
        "regex": {
            "type": str,
        },
        "path": {
            "type": str,
        },
        "message_content_type": {
            "type": str,
            "default": "application/json"
        },
        "content_type": {
            "type": str,
            "default": "application/json"
        },
        'path_params': {
            'type': dict,
            'default': {},
        },
        'url_params': {
            'type': dict,
            'default': {},
        },
        'input_message_data': {
            'type': dict,
            'default': {},
        },
        'output_message_data': {
            'type': dict,
            'default': {},
        },
    },
}
plugin.web_socket_data_skeleton = web_socket_data_skeleton

pre_post_event_data_skeleton = {
    "type": dict,
    "child": {
        "priority": {
            "type": int,
            "default": 10,
        },
    },
}
plugin.pre_post_event_data_skeleton = pre_post_event_data_skeleton

request_event_list = {
    'GET': [],
    'POST': [],
    'PUT': [],
    'DELETE': [],
    'OPTIONS': [],
    'HEAD': [],
}
websocket_event_list = []

pre_request_event_list = []
post_request_event_list = []
websocket_pre_open_event_list = []
websocket_post_open_event_list = []
websocket_pre_message_event_list = []
websocket_post_message_event_list = []
websocket_close_event_list = []
