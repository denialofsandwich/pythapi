#!/usr/bin/python3
# -*- coding: utf-8 -*-

import core.plugin_base

log = None

plugin = core.plugin_base.PythapiPlugin("broken_load")
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
    return True


@core.plugin_base.event(plugin, 'core.load')
def load():
    global log
    log = core.plugin_base.log

    log.debug("I'm alive! 1")
    return False
