#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest

import tests.tools


def _web_base_conf_gen():
    return {
        "core.general": {
            "loglevel": 6,
            "additional_plugin_paths": "plugins/job/tests/plugins",
            "enabled_plugins": "web, job, debug_job",
        },
        "web": {
            "binds": """{
                        "ip": "127.0.0.1",
                        "port": 8223
                    }""",
        }
    }
