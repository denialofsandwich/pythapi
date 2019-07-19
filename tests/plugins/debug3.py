#!/usr/bin/python3
# -*- coding: utf-8 -*-

import core.plugin_base

log = None

plugin = core.plugin_base.PythapiPlugin("debug3")
plugin.version = "1.0"
plugin.essential = False
plugin.info['f_name'] = {
    'EN': 'Debug',
    'DE': 'Bugfix'
}

plugin.info['f_description'] = {
    'EN': 'To test stuff.',
    'DE': 'Um Sachen zu machen.'
}

plugin.info['f_icon'] = {
    'EN': 'storage'
}

plugin.depends = [
    {
        'name': 'debug1',
        'required': True
    }
]

plugin.translation_dict = {
    'DATA_ILLEGAL_CHARACTER_FOUND': {
        'EN': "Invalid character in key name found.",
        'DE': "Ungültiges Zeichen in Schlüsselnamen gefunden."
    }
}

plugin.config_defaults = {}


@core.plugin_base.event(plugin, 'core.check')
def check():
    return True


@core.plugin_base.event(plugin, 'core.load')
def load():
    global log
    log = core.plugin_base.log

    log.debug("I'm alive! 3")


@core.plugin_base.event(plugin, 'core.install')
def install():
    log = core.plugin_base.log

    log.debug("I'm installed! 3")


@core.plugin_base.event(plugin, 'core.uninstall')
def uninstall():
    log = core.plugin_base.log

    log.debug("I'm uninstalled! 3")
