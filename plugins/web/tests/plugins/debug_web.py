#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base
import core.casting

import datetime

log = None

plugin = core.plugin_base.PythapiPlugin("debug_web")
plugin.version = "1.0"
plugin.essential = False

plugin.depends = [
    {
        'name': 'web',
        'required': False
    }
]

plugin.config_defaults = {}


@core.plugin_base.event(plugin, 'core.load', {})
def load():
    global log
    log = core.plugin_base.log


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/hello/*",
    "method": "GET",
    "request_content_type": 'application/json',
    "path_params": {
        "children": {
            "type": int,
        }
    },
    "url_params": {
        "child": {
            "alpha": {
                "type": list,
                "default": [],
                "single_cast_mode": 2,
                "children": {
                    "type": int,
                },
                "child": [{
                    "default": 0,
                }]
            }
        }
    },
    "body_data": {
        "child": {
            "alpha": {
                "type": int,
                "default": 5,
            },
            "charlie": {
                "type": str,
            },
        }
    },
    "response_format": {},
})
def test_web_action(body_data, url_params, **kwargs):
    return {
        "moar": datetime.datetime.now(),
        "body": body_data,
        "up": url_params,
    }


@core.plugin_base.event(plugin, 'web.socket', {
    "path": "/ws/*",
    "method": "GET",
    "message_content_type": 'application/json',
    "path_params": {
        "children": {
            "type": int,
        }
    },
    "url_params": {
        "child": {
            "alpha": {
                "type": list,
                "default": [],
                "single_cast_mode": 2,
                "children": {
                    "type": int,
                },
                "child": [{
                    "default": 0,
                }]
            }
        }
    },
    "input_message_data": {
        "child": {
            "alpha": {
                "type": int,
                "default": 5,
            },
            "charlie": {
                "type": str,
            },
        }
    },
    "output_message_data": {},
})
class TestEchoWebSocket:
    def on_open(self, **kwargs):
        return {
            "data": "I'm alive!",
            "path_params": kwargs['path_params'],
            "url_params": kwargs['url_params'],
        }

    def on_message(self, message_data, **kwargs):
        return {
            "data": message_data,
        }

    def on_close(self, **kwargs):
        print("WebSocket closed")


