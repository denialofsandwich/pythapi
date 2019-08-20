#!/usr/bin/python3
# -*- coding: utf-8 -*-

import core.plugin_base

log = None

plugin = core.plugin_base.PythapiPlugin("broken_check")
plugin.version = "1.0"
plugin.essential = False

plugin.depends = [
    {
        'name': 'debug2',
        'required': False
    }
]

plugin.config_defaults = {}


@core.plugin_base.event(plugin, 'core.check')
def check():
    return False
