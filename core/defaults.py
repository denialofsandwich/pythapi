#!/usr/bin/env python3
# -*- coding: utf-8 -*-

config_defaults = {
    "core.general": {
        "loglevel": {
            "type": int,
            "default": 5
        },
        "colored_logs": {
            "type": bool,
            "default": True
        },
        "file_logging_enabled": {
            "type": bool,
            "default": False
        },
        "logfile": {
            "type": str,
            "default": "pythapilog.log"
        },
        "enabled_plugins": {
            "type": list,
            "default": [],
            "children": {
                "type": str,
            }
        },
        "additional_plugin_paths": {
            "type": list,
            "default": [],
            "children": {
                "type": str,
            }
        },
    },
}

config_base_path = "pythapi.ini"
