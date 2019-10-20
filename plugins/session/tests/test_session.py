#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest

import tests.tools
import core.plugin_base

import requests
import base64
import json
import datetime


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
        },
        "session": {
            "default_expiration_time": str(60*60*24*7),
            "cipher_length": "16",
            "session_cookie_name": "SESSION",
        },
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
    def test_set_insecure_cookie(self, core_system):
        session = core.plugin_base.plugin_dict['session']
        data = 4.55

        r = requests.post(base_url + "/debug_session/insecure_cookie", json={
            "data": data,
        })

        cookie_data = json.loads(base64.b64decode(r.cookies["TEST_COOKIE"]).decode('utf8'))

        assert base64.b64decode(cookie_data['d']) == b'4.55'
        assert session.encode_type[type(data)] == cookie_data['h']['t']
        assert r.json() == {"status": "success"}

    def test_get_insecure_cookie(self, core_system):
        s = requests.Session()
        data = {
            "alpha": "india",
        }

        s.post(base_url + "/debug_session/insecure_cookie", json={
            "data": data,
        })

        r = s.get(base_url + "/debug_session/insecure_cookie")
        assert data == r.json()['data']

    def test_get_no_cookie(self, core_system):
        r = requests.get(base_url + "/debug_session/insecure_cookie")
        assert r.json()['data'] is None

    def test_cookie_with_no_header(self, core_system):
        s = requests.Session()

        # Manipulating Cookie...
        cookie_data = {
            "d": base64.b64encode(b'{"a": "bravo"}').decode('utf8')
        }

        s.cookies.set('TEST_COOKIE', base64.b64encode(json.dumps(cookie_data).encode('utf8')).decode('utf8'))
        r = s.get(base_url + "/debug_session/insecure_cookie")
        assert r.json()['data'] is None

    def test_cookie_corrupt_data(self, core_system):
        s = requests.Session()

        # Manipulating Cookie...
        cookie_data = {
            "h": {
                "t": 0
            },
            "d": "A"
        }

        s.cookies.set('TEST_COOKIE', base64.b64encode(json.dumps(cookie_data).encode('utf8')).decode('utf8'))
        r = s.get(base_url + "/debug_session/insecure_cookie")
        assert r.json()['data'] is None

    def test_wrong_cookie_type(self, core_system):
        s = requests.Session()

        # Manipulating Cookie...
        cookie_data = {
            "h": {
                "t": 0
            },
            "d": "A"
        }

        s.cookies.set('TEST_COOKIE', base64.b64encode(json.dumps(cookie_data).encode('utf8')).decode('utf8'))
        r = s.get(base_url + "/debug_session/signed_cookie")
        assert r.json()['data'] is None

    def test_set_signed_cookie(self, core_system):
        session = core.plugin_base.plugin_dict['session']
        data = "Hallo Welt!"

        r = requests.post(base_url + "/debug_session/signed_cookie", json={
            "data": data,
        })

        cookie_data = json.loads(base64.b64decode(r.cookies["TEST_COOKIE"]).decode('utf8'))

        assert base64.b64decode(cookie_data['d']) == b'Hallo Welt!'
        assert session.encode_type[type(data)] == cookie_data['h']['t']
        assert type(datetime.datetime.strptime(cookie_data['h']['e'], '%Y-%m-%dT%H:%M:%SZ')) is datetime.datetime
        assert len(base64.b64decode(cookie_data['s'])) == 16
        assert r.json() == {"status": "success"}

    def test_expiring_cookie(self, core_system):
        data = "Hallo Welt!"
        expire_time = datetime.datetime.now().replace(microsecond=0) + datetime.timedelta(1, 0)

        r = requests.post(base_url + "/debug_session/expire_cookie", json={
            "expires": expire_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            "data": data,
        })

        cookie_data = json.loads(base64.b64decode(r.cookies["TEST_COOKIE"]).decode('utf8'))
        received_time = datetime.datetime.strptime(cookie_data['h']['e'], '%Y-%m-%dT%H:%M:%SZ')

        assert r.json() == {"status": "success"}
        assert received_time == expire_time

    def test_get_expired_cookie(self, core_system):
        s = requests.Session()
        expire_time = datetime.datetime.now().replace(microsecond=0) - datetime.timedelta(1, 0)
        data = {
            "golf": "hotel",
        }

        r = s.post(base_url + "/debug_session/expire_cookie", json={
            "expires": expire_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            "data": data,
        })

        # Manipulating Cookie...
        s.cookies.set('TEST_COOKIE', r.headers['Set-Cookie'][13:161])

        r = s.get(base_url + "/debug_session/signed_cookie")
        assert r.json()['data'] is None

    def test_get_signed_cookie(self, core_system):
        s = requests.Session()
        data = {
            "golf": "hotel",
        }

        s.post(base_url + "/debug_session/signed_cookie", json={
            "data": data,
        })

        r = s.get(base_url + "/debug_session/signed_cookie")
        assert data == r.json()['data']

        # Manipulating Cookie...
        cookie_data = json.loads(base64.b64decode(s.cookies["TEST_COOKIE"]).decode('utf8'))
        cookie_data['d'] = base64.b64encode(b'{"a": "bravo"}').decode('utf8')
        del s.cookies['TEST_COOKIE']
        s.cookies.set('TEST_COOKIE', base64.b64encode(json.dumps(cookie_data).encode('utf8')).decode('utf8'))

        r = s.get(base_url + "/debug_session/signed_cookie")
        assert r.json()['data'] is None

    def test_set_encrypted_cookie(self, core_system):
        session = core.plugin_base.plugin_dict['session']

        data = "Hallo Welt!"

        r = requests.post(base_url + "/debug_session/encrypted_cookie", json={
            "data": data,
        })

        cookie_data = json.loads(base64.b64decode(r.cookies["TEST_COOKIE"]).decode('utf8'))

        print(cookie_data)

        assert session.encode_type[type(data)] == cookie_data['h']['t']
        assert type(datetime.datetime.strptime(cookie_data['h']['e'], '%Y-%m-%dT%H:%M:%SZ')) is datetime.datetime
        assert len(base64.b64decode(cookie_data['s'])) == 16
        assert r.json() == {"status": "success"}

    def test_get_encrypted_cookie(self, core_system):
        s = requests.Session()
        data = {
            "golf": "hotel",
        }

        s.post(base_url + "/debug_session/encrypted_cookie", json={
            "data": data,
        })

        r = s.get(base_url + "/debug_session/encrypted_cookie")
        assert data == r.json()['data']

        # Manipulating Cookie...
        cookie_data = json.loads(base64.b64decode(s.cookies["TEST_COOKIE"]).decode('utf8'))
        cookie_data['d'] = base64.b64encode(b'{"a": "bravo"}').decode('utf8')
        del s.cookies['TEST_COOKIE']
        s.cookies.set('TEST_COOKIE', base64.b64encode(json.dumps(cookie_data).encode('utf8')).decode('utf8'))

        r = s.get(base_url + "/debug_session/encrypted_cookie")
        assert r.json()['data'] is None

    def test_no_session(self, core_system):
        s = requests.Session()
        s.put(base_url + "/debug_session/session", json={
            "data": {
                "alpha": "juliet"
            }
        })

        r = s.get(base_url + "/debug_session/session")
        assert r.json()['data'] == {}

    def test_session(self, core_system):
        s = requests.Session()
        data = {
            "kilo": "lima"
        }

        s.post(base_url + "/debug_session/session", json={
            "reset": False,
        })
        s.put(base_url + "/debug_session/session", json={
            "data": data
        })

        r = s.get(base_url + "/debug_session/session")
        assert r.json()['data'] == data

        # Test if reset=False works
        s.post(base_url + "/debug_session/session", json={
            "reset": False,
        })

        r = s.get(base_url + "/debug_session/session")
        assert r.json()['data'] == data

    def test_expired_session(self, core_system):
        s = requests.Session()
        data = {
            "mike": "nordpol"
        }

        r = s.post(base_url + "/debug_session/session_time", json={
            "reset": False,
            "expires": (datetime.datetime.now() - datetime.timedelta(1, 0)).strftime('%Y-%m-%dT%H:%M:%SZ')
        })
        s.cookies.set('SESSION', r.headers['Set-Cookie'][9:53])
        s.put(base_url + "/debug_session/session", json={
            "data": data
        })

        r = s.get(base_url + "/debug_session/session")
        assert r.json()['data'] == {}

    def test_reset_session(self, core_system):
        s = requests.Session()
        data = {
            "oscar": "papa"
        }

        s.post(base_url + "/debug_session/session", json={
            "reset": False,
        })
        s.put(base_url + "/debug_session/session", json={
            "data": data
        })

        # Test if reset=True works
        s.post(base_url + "/debug_session/session", json={
            "reset": True,
        })

        r = s.get(base_url + "/debug_session/session")
        assert r.json()['data'] == {}

    def test_session_expire_timedelta(self, core_system):
        s = requests.Session()
        data = {
            "quebec": "sierra"
        }

        s.post(base_url + "/debug_session/session_timedelta", json={
            "reset": False,
            "expires": 600
        })
        s.put(base_url + "/debug_session/session", json={
            "data": data
        })

        r = s.get(base_url + "/debug_session/session")
        assert r.json()['data'] == data

    def test_destroy_session(self, core_system):
        s = requests.Session()
        data = {
            "romeo": "tango"
        }

        s.post(base_url + "/debug_session/session", json={
            "reset": False,
        })
        s.put(base_url + "/debug_session/session", json={
            "data": data
        })

        r = s.get(base_url + "/debug_session/session")
        assert r.json()['data'] == data

        s.delete(base_url + "/debug_session/session")
        r = s.get(base_url + "/debug_session/session")
        assert r.json()['data'] == {}

        s.delete(base_url + "/debug_session/session")
        r = s.get(base_url + "/debug_session/session")
        assert r.json()['data'] == {}
