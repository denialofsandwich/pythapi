#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base

log = None

plugin = core.plugin_base.PythapiPlugin("debug3")
plugin.version = "1.0"
plugin.essential = False

plugin.depends = [
    {
        'name': 'debug1',
        'required': True
    }
]

plugin.config_defaults = {}


@core.plugin_base.event(plugin, 'core.load', {
    "priority": 5,
})
def load():
    global log
    log = core.plugin_base.log

    log.debug("I'm alive! 3")


@core.plugin_base.event(plugin, 'core.uninstall')
def uninstall():
    log = core.plugin_base.log

    log.debug("I'm uninstalled! 3")
