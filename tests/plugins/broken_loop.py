#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base

plugin = core.plugin_base.PythapiPlugin("broken_loop")
plugin.version = "1.0"
plugin.essential = False

plugin.depends = [
    {
        'name': 'broken_loop',
        'required': True
    }
]
