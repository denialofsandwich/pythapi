#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base
import core.casting

plugin = core.plugin_base.PythapiPlugin("info")
plugin.version = "1.0"
plugin.essential = False

plugin.info['f_name'] = {
    '_tr': True,
    'EN': 'Info',
}

plugin.info['f_description'] = {
    '_tr': True,
    'EN': 'Provides informations about plugins and events.',
    'DE': 'Stellt Informationen über Plugins und Events bereit.'
}

plugin.depends = [
    {
        "name": "web",
        "required": True,
    }
]

plugin.config_defaults = {
    plugin.name: {},
}

plugin.PluginNotFoundException = None
plugin.RequestNotFoundException = None


def check_plugin_existence(val, _env, **kwargs):
    if val not in core.plugin_base.plugin_dict:
        raise plugin.PluginNotFoundException(val)

    _env['plugin_name'] = val
    return val


def check_request_existence(val, _env, **kwargs):
    web = core.plugin_base.plugin_dict['web']
    plugin_name = _env.get('plugin_name', None)

    if val not in web.request_name_table[plugin_name]:
        raise plugin.RequestNotFoundException(val)

    return val


plugin.web_template_table = {
    "plugin_name": {
        "type": str,
        "regex": r"[_a-zA-Z0-9-]+",
        "pre_format": check_plugin_existence,
        "f_name": {
            "_tr": True,
            "EN": "Plugin name",
            "DE": "Plugin Name"
        }
    },
    "request_name": {
        "type": str,
        "regex": r"[_a-zA-Z0-9-]+",
        "pre_format": check_request_existence,
        "f_name": {
            "_tr": True,
            "EN": "Request name",
            "DE": "Request Name"
        }
    },
}
