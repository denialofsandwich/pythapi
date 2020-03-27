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


@core.plugin_base.event(plugin, 'core.terminate')
def terminate():
    core.plugin_base.log.debug("TERMINATATA")
