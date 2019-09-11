#!/usr/bin/env python3
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
        "binds": {
            "type": list,
            "delimiter": ';',
            "default": [
                {
                    "ip": "127.0.0.1",
                    "port": 8123,
                    "api_only": True,
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
                    "static_web_server": {
                        "type": bool,
                        "default": False,
                    },
                    "api_base_url": {
                        "type": str,
                        "default": "",
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
        val['_raw_regex'] = ['^', '/' + kwargs['d_plugin_name'] + val['path'].replace('*', '([^/]*)') + '$']
        val['regex'] = ''.join(val['_raw_regex'])

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
        'body_data': {
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
        "regex": {
            "type": str,
        },
        "path": {
            "type": str,
        },
        "input_message_content_type": {
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
        'input_message_format': {
            'type': dict,
            'default': {},
        },
        'output_message_message_format': {
            'type': dict,
            'default': {},
        },
        'response_format': {
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

request_event_list = {}
websocket_event_list = []

pre_request_event_list = []
post_request_event_list = []
websocket_pre_open_event_list = []
websocket_post_open_event_list = []
websocket_pre_message_event_list = []
websocket_post_message_event_list = []
websocket_close_event_list = []

request_prefix_table = {}


plugin.exception_list = {
    "ERROR_GENERAL_NOT_FOUND": {
        "error_id": "ERROR_GENERAL_NOT_FOUND",
        "status_code": 404,
        "message": {
            "_multi_lingual": True,
            "DE": "Die angeforderte Ressource wurde nicht gefunden.",
            "EN": "Can't find the requested resource.",
        }
    }
}


@core.plugin_base.external(plugin)
class WebRequestException(Exception):
    def __init__(self, error_id='ERROR_GENERAL_UNKNOWN', status_code=400, data=None, tpl=None):
        if tpl:
            error_id = tpl.get("error_id", None) or error_id
            status_code = tpl.get("status_code", None) or status_code

        self.error_id = error_id
        self.message = None
        self.status_code = status_code
        self.data = data or {}
        Exception.__init__(self, self.message)
