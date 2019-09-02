#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base

log = None

plugin = core.plugin_base.PythapiPlugin("debug1")


@core.plugin_base.event(plugin, 'core.init')
def init():
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


@core.plugin_base.event(plugin, 'core.load_optional')
def load_optional():
    log.debug("I'm load optional! 2")
    return True


@core.plugin_base.event(plugin, 'core.uninstall')
def uninstall():
    log = core.plugin_base.log

    log.debug("I'm uninstalled! 1")
