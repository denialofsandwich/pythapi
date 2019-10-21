#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base

plugin = core.plugin_base.PythapiPlugin("mongo_link")
plugin.version = "1.0"
plugin.essential = False

plugin.info['f_name'] = {
    'EN': 'Mongo-Link'
}

plugin.info['f_description'] = {
    'EN': 'Connects to a MongoDB.',
    'DE': 'Stellt eine Verbindung zu einer MongoDB bereit.'
}

plugin.depends = [
    {
        "name": "web",
        "required" : True
     },
]

plugin.config_defaults = {
    plugin.name: {
        "host": {
            "type": str,
            "default": "localhost"
        },
        "port": {
            "type": int,
            "default": 27017,
        },
        "auth_source": {
            "type": str,
            "default": "admin",
        }
    }
}
