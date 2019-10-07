#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base
import core.casting

plugin = core.plugin_base.PythapiPlugin("debug_info")
plugin.version = "1.0"
plugin.essential = False

plugin.depends = [
    {
        'name': 'info',
        'required': True
    }
]

plugin.config_defaults = {}
