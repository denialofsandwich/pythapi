#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest

import tests.tools
import core.plugin_base

import datetime
import time
import requests


# TODO: Um sicherzustellen, dass alle Zeichen bei den Cookies funktionieren (da ich nicht base64 kodieren werde),
#       sollte ich auch möglichst alle Zeichen Testen
#   Insbesondere: ; " ,


base_url = "http://127.0.0.1:18223"


@pytest.fixture(scope='function')
def cs_bare():
    yield tests.tools.CoreSystem()


def _job_base_conf_gen():
    return {
        "core.general": {
            "loglevel": 6,
            "additional_plugin_paths": "plugins/session/tests/plugins",
            "enabled_plugins": "web, session, debug_session",
        },
        "web": {
            "binds": """{
                        "ip": "127.0.0.1",
                        "port": 18223
                    }""",
        }
    }


@pytest.fixture(scope='function')
def job_base_conf():
    yield _job_base_conf_gen()


@pytest.fixture(scope='class')
def core_system():
    cs = tests.tools.CoreSystem()
    cs.conf = _job_base_conf_gen()

    with cs:
        yield cs
