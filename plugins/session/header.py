#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base

plugin = core.plugin_base.PythapiPlugin("session")
plugin.version = "1.0"
plugin.essential = False

plugin.info['f_name'] = {
    '_tr': True,
    'EN': 'Session'
}

plugin.info['f_description'] = {
    '_tr': True,
    'EN': 'Manages sessions and handles cookies.',
    'DE': 'Verwaltet Sessions und Cookies.'
}

plugin.depends = [
    {
        "name": "web",
        "required": True,
    }
]

plugin.config_defaults = {
    plugin.name: {
        "secret": {
            "type": str,
            "regex": r".{64,}",
        },
        "default_expiration_time": {
            "type": int,
            "default": 60*60*24*7,  # 7 Days
        }
    },
}
