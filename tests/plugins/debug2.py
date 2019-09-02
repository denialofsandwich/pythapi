#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base

plugin = core.plugin_base.PythapiPlugin("debug2")
plugin.version = "1.0"
plugin.essential = False

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
