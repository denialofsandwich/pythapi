#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base

plugin = core.plugin_base.PythapiPlugin("job")
plugin.version = "1.0"
plugin.essential = False

plugin.info['f_name'] = {
    'EN': 'Jobs'
}

plugin.info['f_description'] = {
    'EN': 'Provides functionalities for background processes.',
    'DE': 'Stellt Funktionalitäten für Hintergrundprozesse bereit.'
}

plugin.depends = [
    {
        "name": "web",
        "required": False,
    }
]

plugin.config_defaults = {
    plugin.name: {},
}
