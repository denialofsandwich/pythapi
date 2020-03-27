#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base

plugin = core.plugin_base.PythapiPlugin("auth")
plugin.version = "1.0"
plugin.essential = True

plugin.info['f_name'] = {
    '_tr': True,
    'EN': 'Authentication',
    'DE': 'Authentifizierung',
}

plugin.info['f_description'] = {
    '_tr': True,
    'EN': 'This Plugin provides features to authenticate users.',
    'DE': 'Dieses Plugin stellt Funktionalitäten zur Authentifizierung von Benutzern bereit.',
}

plugin.depends = [
    {
        "name": "web",
        "required": True,
    },
    {
        "name": "mongo_link",
        "required": True,
    },
    {
        "name": "session",
        "required": True,
    }
]

plugin.config_defaults = {
    plugin.name: {},
}

plugin.web_template_table = {}
