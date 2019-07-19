#!/usr/bin/python3
# -*- coding: utf-8 -*-

import core.plugin_base
from core.plugin_base import log

plugin = core.plugin_base.PythapiPlugin("debug2")
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
        'name': 'debug3',
        'required': True
    }
]

plugin.config_defaults = {
    plugin.name: {
        "enabled_plugins": {
            "type": list,
            "children": {
                "type": str,
            }
        },
    }
}


#@core.plugin_base.event(plugin, 'core.check')
#def check():
#    return True


#@core.plugin_base.event(plugin, 'core.load')
#def load():
#    log.debug("I'm alive! 2")
#    return True


#@core.plugin_base.event(plugin, 'core.install')
#def install():
#    log.debug("I'm installed! 2")


#@core.plugin_base.event(plugin, 'core.uninstall')
#def uninstall():
#    log.debug("I'm uninstalled! 2")
