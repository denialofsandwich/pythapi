#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base
import core.casting
from tornado import gen

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


@core.plugin_base.event(plugin, 'web.socket.close')
def test_web_socket_close(env, event_data):
    core.plugin_base.log.debug("CLOSE_EVENT")


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/u_there",
})
def test_req_basic(**kwargs):
    return {
        "answer": "yes"
    }


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/u_there2",
})
def test_amb1(**kwargs):
    return {
        "answer": "yes"
    }


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/u_there2",
})
def test_amb1(**kwargs):
    return {
        "answer": "yes"
    }


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/url_arg1",
})
def test_req_url_args(url_params, **kwargs):
    return {
        "data": url_params,
    }


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/url_arg2",
    "method": "GET",
    "url_params": {
        "child": {
            "hello": {
                "type": list,
                "single_cast_mode": 2,
                "children": {
                    "type": str
                }
            }
        }
    }
})
@gen.coroutine
def test_req_url_args2(url_params, **kwargs):
    return {
        "data": url_params,
    }


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/path_arg1/*/*",
})
def test_req_path_args1(path_params, **kwargs):
    return {
        "data": path_params,
    }


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/path_arg2/*/*",
    "path_params": {
        "child": [
            {
                "type": int
            },
            {
                "type": bool
            }
        ]
    },
})
def test_req_path_args2(path_params, **kwargs):
    return {
        "data": path_params,
    }


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/body_data1",
    "method": "POST",
})
def test_req_path_args2(body_data, **kwargs):
    return {
        "data": body_data,
    }


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/body_data2",
    "method": "POST",
    "body_data": {
        "child": {
            "alfa": {
                "type": int,
                "default": 45,
            },
            "bravo": {
                "type": bool,
            }
        }
    },
})
def test_req_path_args2(body_data, **kwargs):
    return {
        "data": body_data,
    }


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/empty_response",
})
def test_empty_response(**kwargs):
    return


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/throw_exception",
})
def test_throw_exception(**kwargs):
    raise Exception("This is an Exception")


@core.plugin_base.event(plugin, 'web.socket', {
    "path": "/ws_base"
})
class TestBaseWebSocket:
    def on_open(self, **kwargs):
        return {
            "data": "Hello my friend!",
        }

    def on_message(self, message_data, **kwargs):
        return {
            "data": message_data,
        }

    def on_close(self, **kwargs):
        core.plugin_base.log.debug("DONE")


@core.plugin_base.event(plugin, 'web.socket', {
    "path": "/ws_url_params",
    "url_params": {
        "child": {
            "alpha": {
                "type": list,
                "default": [],
                "single_cast_mode": 2,
                "child": [{
                    "type": int,
                }]
            }
        }
    },
})
class TestURLParams:
    def on_open(self, url_params, **kwargs):
        return {
            "data": url_params,
        }


@core.plugin_base.event(plugin, 'web.socket', {
    "path": "/ws_path_params/*/*",
    "path_params": {
        "child": [
            {
                "type": int,
            },
            {
                "type": float,
            }
        ],
    },
})
class TestPathParams:
    def on_open(self, path_params, **kwargs):
        return {
            "data": path_params,
        }


@core.plugin_base.event(plugin, 'web.socket', {
    "path": "/ws_message",
    "input_message_format": {
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
    "output_message_message_format": {
        "type": dict,
        "child": {
            "delta": {
                "type": int,
                "default": 45,
            }
        }
    },
})
class TestMessageFormatter:
    def on_message(self, message_data, **kwargs):
        return {
            "data": message_data,
        }


@core.plugin_base.event(plugin, 'web.socket', {
    "path": "/ws_except1"
})
class TestExceptionSocket1:
    def on_open(self, **kwargs):
        raise Exception("This is an Exception")


@core.plugin_base.event(plugin, 'web.socket', {
    "path": "/ws_except2"
})
class TestExceptionSocket1:
    def on_message(self, **kwargs):
        raise Exception("This is an Exception")


@core.plugin_base.event(plugin, 'web.socket', {
    "path": "/ws_except3"
})
class TestExceptionSocket1:
    def on_close(self, **kwargs):
        raise Exception("This is an Exception")


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/throw_custom_exception",
})
def test_throw_custom_exception(**kwargs):
    web = core.plugin_base.plugin_dict['web']
    raise web.WebRequestException(tpl=web.exception_list['ERROR_GENERAL_NOT_FOUND'], data={
        "test": True
    })
