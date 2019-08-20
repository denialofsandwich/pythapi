#!/usr/bin/python3
# -*- coding: utf-8 -*-

import core.plugin_base

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


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/hello/world",
    "method": "GET",
})
def test_web_action(**kwargs):
    print("I'm alive!")
    web = core.plugin_base.plugin_dict['web']
    web.test_external_function("HALLOWEEEEN!")
    return True
