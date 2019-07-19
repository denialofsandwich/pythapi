#!/usr/bin/python3
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
#    "core.web": {
#        "http_port": {"type": list, "default": [8123], "children": {"type": int}},
#        "bind_ip": {"type": str, "default": "127.0.0.1"},
#        "https_enabled": {"type": bool, "default": False},
#        "https_port": {"type": list, "default": [8124], "children": {"type": int}},
#        "ssl_cert_file": {"type": str, "default": "certfile.pem"},
#        "ssl_key_file": {"type": str, "default": "keyfile.pem"},
#        "additional_header": {"type": list, "default": [], "children": {
#            "type": list,
#            "delimiter": ':',
#            "children": {
#                "type": str
#            }
#        }},
#    },
}

config_base_path = "pythapi.ini"
