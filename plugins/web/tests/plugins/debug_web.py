#!/usr/bin/python3
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
    "response_format": {
        "type_defaults": {
            datetime.datetime: {
                'pre_format': lambda val, **kwargs: val.strftime("%Y:%m:%d"),
            },
        }
    },
})
def test_web_action(body_data, **kwargs):
    web = core.plugin_base.plugin_dict['web']
    return {
        "moar": datetime.datetime.now(),
        "web": web,
        "data": core.plugin_base.config[web.name]['additional_headers'],
        "body": body_data,
    }


#@core.plugin_base.event(plugin, 'web.socket', {
#    "path": "/ws",
#    "method": "GET",
#    "request_content_type": 'application/json',
#    "path_params": {
#        "children": {
#            "type": int,
#        }
#    },
#    "url_params": {
#        "child": {
#            "alpha": {
#                "type": list,
#                "default": [],
#                "single_cast_mode": 2,
#                "children": {
#                    "type": int,
#                },
#                "child": [{
#                    "default": 0,
#                }]
#            }
#        }
#    },
#    "body_data": {
#        "child": {
#            "alpha": {
#                "type": int,
#                "default": 5,
#            },
#            "charlie": {
#                "type": str,
#            },
#        }
#    },
#    "response_format": {
#        "type_defaults": {
#            datetime.datetime: {
#                'pre_format': lambda val, **kwargs: val.strftime("%Y:%m:%d"),
#            },
#        }
#    },
#})
#class EchoWebSocket(tornado.websocket.WebSocketHandler):
#    def open(self):
#        log.debug(vars(self.request))
#        print("WebSocket opened")
#
#    def on_message(self, message):
#        self.write_message(u"You said: " + message)
#
#    def on_close(self):
#        print("WebSocket closed")


