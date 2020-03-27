#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base

log = None

plugin = core.plugin_base.PythapiPlugin("debug1")

plugin.version = "1.0"
plugin.essential = False

plugin.depends = [
    {
        'name': 'debug2',
        'required': False
    }
]

plugin.config_defaults = {}


@core.plugin_base.external(plugin)
def external_func():
    return 4


@core.plugin_base.event(plugin, 'core.declare')
def declare():
    global log
    log = core.plugin_base.log

    log.debug("I'm declared!")


@core.plugin_base.event(plugin, 'core.load')
def load():
    global log
    log = core.plugin_base.log

    log.debug("I'm alive! 1")


@core.plugin_base.event(plugin, 'core.load_optional')
def load_optional():
    log.debug("I'm load optional! 1")
    return True


@core.plugin_base.event(plugin, 'core.uninstall')
def uninstall():
    log = core.plugin_base.log

    log.debug("I'm uninstalled! 1")
