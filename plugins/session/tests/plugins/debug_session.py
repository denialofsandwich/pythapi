#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base
import core.casting

plugin = core.plugin_base.PythapiPlugin("debug_session")
plugin.version = "1.0"
plugin.essential = False

plugin.depends = [
    {
        'name': 'session',
        'required': True
    }
]

plugin.config_defaults = {}


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/set",
})
def test_set_cookie(request_obj, **kwargs):
    session = core.plugin_base.plugin_dict['session']
    session.set_cookie(request_obj, "DATA", {
        "alpha": "bravo",
        "hotel": "golf",
    })

    return {}


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/get",
})
def test_get_cookie(request_obj, **kwargs):
    return {
        "data": request_obj.get_cookie("test"),
    }
