#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base
import core.casting
import re

plugin = core.plugin_base.PythapiPlugin("web")
plugin.version = "1.0"
plugin.essential = False

plugin.info['f_name'] = {
    'EN': 'Webserver'
}

plugin.info['f_description'] = {
    'EN': 'Provides a HTTP-API-interface.',
    'DE': 'Stellt ein HTTP API-Interface bereit.'
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


plugin.web_exception_list = {
    "ERROR_GENERAL_BAD_REQUEST": {
        "error_id": "ERROR_GENERAL_BAD_REQUEST",
        "status_code": 400,
        "message": {
            "_tr": True,
            "DE": "Fehlerhaftes Anfrageformat.",
            "EN": "Incorrect request format.",
        }
    },
    "ERROR_GENERAL_UNAUTHORIZED": {
        "error_id": "ERROR_GENERAL_UNAUTHORIZED",
        "status_code": 401,
        "message": {
            "_tr": True,
            "DE": "Es wird eine Authentifikation benötigt.",
            "EN": "Authentication required.",
        }
    },
    "ERROR_GENERAL_FORBIDDEN": {
        "error_id": "ERROR_GENERAL_FORBIDDEN",
        "status_code": 403,
        "message": {
            "_tr": True,
            "DE": "Unzureichende Berechtigungen.",
            "EN": "Insufficient permissions.",
        }
    },
    "ERROR_GENERAL_NOT_FOUND": {
        "error_id": "ERROR_GENERAL_NOT_FOUND",
        "status_code": 404,
        "message": {
            "_tr": True,
            "DE": "Die angeforderte Ressource wurde nicht gefunden.",
            "EN": "Can't find the requested resource.",
        }
    },
    "ERROR_GENERAL_METHOD_NOT_ALLOWED": {
        "error_id": "ERROR_GENERAL_METHOD_NOT_ALLOWED",
        "status_code": 405,
        "message": {
            "_tr": True,
            "DE": "Die verwendete Methode wird nicht unterstützt.",
            "EN": "The method used is not supported.",
        }
    },
    "ERROR_GENERAL_INTERNAL": {
        "error_id": "ERROR_GENERAL_INTERNAL",
        "status_code": 500,
        "message": {
            "_tr": True,
            "DE": "Hier wurde schlecht programmiert.",
            "EN": "You've just experienced bad programming in action.",
        }
    }
}


@core.plugin_base.external(plugin)
def format_tr_table(var, **kwargs):

    if type(var) is dict and var.get('_tr', False):
        raw_languages = kwargs['request_obj'].request.headers.get("Accept-Language", 'en').split(',')

        for lang in raw_languages:
            lang = lang.split(';')[0].upper()
            if lang in var:
                return var[lang]

        return var['EN']

    return var


@core.plugin_base.external(plugin)
class WebRequestException(Exception):
    def __init__(self, error_id='ERROR_GENERAL_UNKNOWN', status_code=400, message="N/A", data=None, tpl=None):
        if tpl:
            error_id = tpl.get("error_id", None) or error_id
            status_code = tpl.get("status_code", None) or status_code
            message = tpl.get("message", None) or message

        self.error_id = error_id
        self.message = message
        self.status_code = status_code
        self.data = data or {}
        Exception.__init__(self, self.message)
