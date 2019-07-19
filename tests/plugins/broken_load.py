#!/usr/bin/python3
# -*- coding: utf-8 -*-

import core.plugin_base
from core.plugin_base import log

plugin = core.plugin_base.PythapiPlugin("broken_load")
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
        'name': 'debug2',
        'required': False
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
    log.debug("I'm alive! 1")
    return False


@core.plugin_base.event(plugin, 'core.load_optional')
def load_optional():
    log.debug("I'm load optional! 2")
    return True


@core.plugin_base.event(plugin, 'core.install')
def install():
    log.debug("I'm installed! 1")


@core.plugin_base.event(plugin, 'core.uninstall')
def uninstall():
    log.debug("I'm uninstalled! 1")
