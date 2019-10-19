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
            "pipe": [{"type": bytes}],
        },
        "default_expiration_time": {
            "type": int,
            "default": 60*60*24*7,  # 7 Days
            "min_val": 0,
        },
        "cipher_length": {
            "type": str,
            "regex": r"16|24|32",
            "default": "16",
            "pipe": [
                {"type": int}
            ],
        },
        "session_cookie_name": {
            "type": str,
            "regex": r"[a-zA-Z0-9_-]+",
            "default": "SESSION",
        },
    },
}

plugin.decode_type = {
    0: dict,
    1: list,
    2: str,
    3: int,
    4: float,
}
plugin.encode_type = {v: k for k, v in plugin.decode_type.items()}


secret = None
crypt_key = None

session_table = {}
