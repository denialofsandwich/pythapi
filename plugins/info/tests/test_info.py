#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest

import tests.tools

import requests


base_url = "http://127.0.0.1:18223"


@pytest.fixture(scope='function')
def cs_bare():
    yield tests.tools.CoreSystem()


def _job_base_conf_gen():
    return {
        "core.general": {
            "loglevel": 6,
            "enabled_plugins": "web, info",
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


class TestSeries:
    def test_list_plugins(self, core_system):
        r = requests.get(base_url + "/info/plugin/list").json()
        assert set(r['data']) == {"web", "info"}

    def test_list_plugins_verbose(self, core_system):
        r = requests.get(base_url + "/info/plugin/list?verbose=true").json()

        assert r['data']['info']['info'] == {
            "f_name": "Info",
            "f_description": "Provides informations about plugins and events.",
        }
        assert r['data']['info']['plugin_name'] == "info"

    def test_get_plugin(self, core_system):
        r = requests.get(base_url + "/info/plugin/name/info?verbose=true").json()

        assert r['data']['info'] == {
            "f_name": "Info",
            "f_description": "Provides informations about plugins and events.",
        }
        assert r['data']['plugin_name'] == "info"

    def test_list_requests_of_plugin(self, core_system):
        r = requests.get(base_url + "/info/request/info/list").json()
        assert set(r['data']) == {
            "get_request_of_plugin",
            "list_plugins",
            "get_plugin",
            "list_requests_of_plugin",
        }

    def test_list_requests_of_plugin_verbose(self, core_system):
        r = requests.get(base_url + "/info/request/info/list?verbose=true").json()

        assert r['data']['get_plugin']['f_name'] == "Get plugin"
        assert r['data']['get_plugin']['f_description'] == "Returns information about a single plugin."
        assert r['data']['get_plugin']['path'] == "/plugin/name/*"

    def test_get_request_of_plugin(self, core_system):
        r = requests.get(base_url + "/info/request/info/name/get_plugin").json()

        assert r['data']['f_name'] == "Get plugin"
        assert r['data']['f_description'] == "Returns information about a single plugin."
        assert r['data']['path'] == "/plugin/name/*"

    def test_plugin_not_found(self, core_system):
        response = requests.get(base_url + "/info/request/lala/name/get_plugin").json()
        assert response == {
            "status": "error",
            "error_id": "ERROR_PLUGIN_NOT_FOUND",
            "message": "Plugin \"lala\" does not exist.",
            "plugin_name": "lala",
        }

    def test_request_not_found(self, core_system):
        response = requests.get(base_url + "/info/request/info/name/lulu").json()
        assert response == {
            "status": "error",
            "error_id": "ERROR_REQUEST_NOT_FOUND",
            "message": "Request \"lulu\" does not exist.",
            "request_name": "lulu",
        }