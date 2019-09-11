#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest

import tests.tools

import re
import requests
import websockets
import asyncio
import json
import copy
import os
import warnings

import core.plugin_base

base_url = "http://127.0.0.1:8223"
ws_base_url = "ws://127.0.0.1:8223"


@pytest.fixture(scope='function')
def cs_bare():
    yield tests.tools.CoreSystem()


def _web_base_conf_gen():
    return {
        "core.general": {
            "loglevel": 6,
            "additional_plugin_paths": "plugins/web/tests/plugins",
            "enabled_plugins": "web, debug_web",
        },
        "web": {
            "binds": """{
                        "ip": "127.0.0.1",
                        "port": 8223
                    }""",
        }
    }


@pytest.fixture(scope='function')
def web_base_conf():
    yield _web_base_conf_gen()


@pytest.fixture(scope='class')
def core_system():
    cs = tests.tools.CoreSystem()
    cs.conf = _web_base_conf_gen()

    with cs:
        yield cs


def test_plain_start(capsys, cs_bare, web_base_conf):
    cs_bare.conf = web_base_conf

    with cs_bare:
        pass

    logs = capsys.readouterr().out
    print(logs)

    # Port Open?
    assert len(re.findall(re.escape("Opened port at: 127.0.0.1:8223, ssl: False, static_web_server: False"), logs)) == 1

    # Detect ambiguous path
    assert len(re.findall(re.escape("Ambiguous path found: ^/debug_web/u_there2$"), logs)) == 1

    # Any Errors?
    assert len(re.findall(r'ERROR|CRITICAL', logs)) == 0


def test_basic_request(cs_bare, web_base_conf, capsys):
    cs_bare.conf = web_base_conf

    with cs_bare:
        response = requests.get(base_url + "/debug_web/u_there").json()
        assert response == {"answer": "yes", "status": "success"}

    logs = capsys.readouterr().out
    print("AA {} AA".format(logs))

    assert len(re.findall('[0-9]+' + ' ' + re.escape("127.0.0.1 GET /debug_web/u_there"), logs)) == 1

    # Any Errors?
    assert len(re.findall(r'ERROR|CRITICAL', logs)) == 0


def test_not_found(cs_bare, web_base_conf, capsys):
    cs_bare.conf = web_base_conf

    with cs_bare:
        response = requests.get(base_url + "/debug_web/not_there").json()
        assert response == {
            'message': "Request doesn't exist.",
            'status': 'error',
            'error_id': 'ERROR_GENERAL_NOT_FOUND'
        }

    logs = capsys.readouterr().out
    print(logs)

    assert len(re.findall('[1-9][0-9]*' + ' ' + re.escape("error 404 ERROR_GENERAL_NOT_FOUND"), logs)) == 1

    # Any Errors?
    assert len(re.findall(r'ERROR[^_]|CRITICAL', logs)) == 0


def test_additional_headers(cs_bare, web_base_conf):
    web_base_conf['web']['additional_headers'] = "A-Header: True"
    cs_bare.conf = web_base_conf

    with cs_bare:
        response = requests.get(base_url + "/debug_web/u_there")
        assert response.headers['A-Header'] == "True"


def test_basic_ws(cs_bare, web_base_conf, capsys):
    cs_bare.conf = web_base_conf

    with cs_bare:
        async def ws_worker():
            uri = ws_base_url + "/debug_web/ws_base"
            async with websockets.connect(uri) as websocket:
                response = await websocket.recv()
                assert json.loads(response) == {
                    'data': 'Hello my friend!',
                    'status': 'success',
                }

                await websocket.send(json.dumps({
                    "golf": "hotel",
                }))
                response = await websocket.recv()
                assert json.loads(response) == {
                    'data': {
                        "golf": "hotel",
                    },
                    'status': 'success',
                }

        asyncio.get_event_loop().run_until_complete(ws_worker())

    logs = capsys.readouterr().out
    print(logs)

    assert len(re.findall('[1-9][0-9]*' + ' ' + re.escape("127.0.0.1 SOCKOPEN /debug_web/ws_base"), logs)) == 1
    assert len(re.findall('[1-9][0-9]*' + ' ' + re.escape("SOCKCLOSE"), logs)) == 1
    assert len(re.findall('DONE', logs)) == 1
    assert len(re.findall('CLOSE_EVENT', logs)) == 1

    # Any Errors?
    assert len(re.findall(r'ERROR[^_]|CRITICAL', logs)) == 0


def test_base_get_client_ip_non_local():
    class req_obj:
        class request:
            remote_ip = "127.0.0.5"

    assert core.plugin_base.module_dict['web'].base._get_client_ip(req_obj) == "127.0.0.5"


def test_static_webserver_undefined_error(cs_bare, web_base_conf, capsys):
    web_base_conf['web']['binds'] = json.dumps({
        "ip": "127.0.0.1",
        "port": 8223,
        "static_web_server": True,
    })
    cs_bare.conf = web_base_conf

    with cs_bare:
        pass

    logs = capsys.readouterr().out
    print(logs)

    assert len(re.findall(re.escape("Static root directory not defined!"), logs)) > 0


def test_static_webserver_not_found_error(cs_bare, web_base_conf, capsys):
    web_base_conf['web']['binds'] = json.dumps({
        "ip": "127.0.0.1",
        "port": 8223,
        "static_web_server": True,
        "static_root": "/tmp/web_root"
    })
    cs_bare.conf = web_base_conf

    try:
        os.remove("/tmp/web_root/index.html")
        os.rmdir("/tmp/web_root")
    except FileNotFoundError:
        pass

    with cs_bare:
        pass

    logs = capsys.readouterr().out
    print(logs)

    assert len(re.findall(re.escape("Static root directory not found!"), logs)) > 0


def test_static_webserver(cs_bare, web_base_conf):
    web_base_conf['web']['binds'] = json.dumps({
        "ip": "127.0.0.1",
        "port": 8223,
        "static_web_server": True,
        "static_root": "/tmp/web_root",
        "api_base_url": "/api"
    })
    cs_bare.conf = web_base_conf

    try:
        os.mkdir("/tmp/web_root")
        with open("/tmp/web_root/index.html", 'w') as f:
            f.write("bravo")
    except FileExistsError:
        pass

    with cs_bare:
        response = requests.get(base_url + "/").text
        assert response == "bravo"

        response = requests.get(base_url + "/api/debug_web/u_there").json()
        assert response == {"answer": "yes", "status": "success"}

    try:
        os.remove("/tmp/web_root/index.html")
        os.rmdir("/tmp/web_root")
    except FileNotFoundError:
        pass


def test_ssl_key_not_defined(cs_bare, web_base_conf, capsys):
    p_dir = os.path.dirname(core.plugin_base.module_dict['web'].__file__)
    web_base_conf['web']['binds'] = json.dumps({
        "ip": "127.0.0.1",
        "port": 8223,
        "ssl": True,
        "cert_file": os.path.join(p_dir, "tests/ssl/test.crt"),
    })
    cs_bare.conf = web_base_conf

    with cs_bare:
        pass

    logs = capsys.readouterr().out
    print(logs)

    assert len(re.findall(re.escape("keyfile not defined!"), logs)) > 0


def test_ssl_cert_not_found(cs_bare, web_base_conf, capsys):
    p_dir = os.path.dirname(core.plugin_base.module_dict['web'].__file__)
    web_base_conf['web']['binds'] = json.dumps({
        "ip": "127.0.0.1",
        "port": 8223,
        "ssl": True,
        "cert_file": os.path.join(p_dir, "tests/ssl/testa.crt"),
        "key_file": os.path.join(p_dir, "tests/ssl/test.key"),
    })
    cs_bare.conf = web_base_conf

    with cs_bare:
        pass

    logs = capsys.readouterr().out
    print(logs)

    assert len(re.findall(re.escape("certfile not found!"), logs)) > 0


def test_ssl_request(cs_bare, web_base_conf):
    p_dir = os.path.dirname(core.plugin_base.module_dict['web'].__file__)
    web_base_conf['web']['binds'] = json.dumps({
        "ip": "127.0.0.1",
        "port": 8223,
        "ssl": True,
        "cert_file": os.path.join(p_dir, "tests/ssl/test.crt"),
        "key_file": os.path.join(p_dir, "tests/ssl/test.key"),
    })
    cs_bare.conf = web_base_conf

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with cs_bare:
            response = requests.get("https://127.0.0.1:8223/debug_web/u_there", verify=False).json()
            assert response == {"answer": "yes", "status": "success"}


class TestFormatter:
    def test_method_not_allowed(self, core_system):
        response = requests.post(base_url + "/debug_web/u_there").json()
        assert response == {
            "status": "error",
            "error_id": "ERROR_GENERAL_METHOD_NOT_ALLOWED",
            'message': "Method not allowed.",
        }

    def test_empty_url_args(self, core_system):
        response = requests.get(base_url + "/debug_web/url_arg1?hello=world&hello=worldardo").json()
        assert response == {
            "data": {
                "hello": [
                    "world",
                    "worldardo"
                ],
                "_pretty": []
            },
            "status": "success"
        }

    def test_filled_url_args(self, core_system):
        response = requests.get(base_url + "/debug_web/url_arg2?hello=world").json()
        assert response == {
            "data": {
                "hello": "world",
                "_pretty": []
            },
            "status": "success"
        }

        response = requests.get(base_url + "/debug_web/url_arg2").json()
        assert response == {
            "path": ".hello",
            "status": "error",
            "section": "url_params",
            "message": "This Value must be set.",
            "error_id": "ERROR_GENERAL_FORMAT"
        }

    def test_empty_path_params(self, core_system):
        response = requests.get(base_url + "/debug_web/path_arg1/hello/world").json()
        assert response == {
            "data": [
                "hello",
                "world"
            ],
            "status": "success"
        }

    def test_filled_path_params(self, core_system):
        response = requests.get(base_url + "/debug_web/path_arg2/56/true").json()
        assert response == {
            "status": "success",
            "data": [
                56,
                True
            ]
        }

        response = requests.get(base_url + "/debug_web/path_arg2/charlie/hotel").json()
        assert response == {
            "error_id": "ERROR_GENERAL_FORMAT",
            "message": "Can't convert \"charlie\" to int",
            "section": "path_params",
            "path": ".0",
            "status": "error"
        }

    def test_empty_body_data(self, core_system):
        response = requests.post(base_url + "/debug_web/body_data1", json={
            "delta": "D",
            "echo": "foxtrot",
        }).json()
        assert response == {
            "status": "success",
            "data": {
                "echo": "foxtrot",
                "delta": "D"
            }
        }

    def test_filled_body_data(self, core_system):
        response = requests.post(base_url + "/debug_web/body_data2", json={
            "delta": "D",
            "echo": "foxtrot",
            "bravo": True,
        }).json()
        assert response == {
            "status": "success",
            "data": {
                "echo": "foxtrot",
                "bravo": True,
                "alfa": 45,
                "delta": "D"
            }
        }

        response = requests.post(base_url + "/debug_web/body_data2", json={
            "delta": "D",
            "echo": "foxtrot",
        }).json()
        assert response == {
            "section": "body_data",
            "status": "error",
            "error_id": "ERROR_GENERAL_FORMAT",
            "message": "This Value must be set.",
            "path": ".bravo"
        }

    def test_empty_response(self, core_system):
        response = requests.get(base_url + "/debug_web/empty_response").json()
        assert response == {
            "status": "success"
        }

    def test_pretty_response(self, core_system):
        response = requests.get(base_url + "/debug_web/empty_response?_pretty=true")
        print(response.text)
        assert response.text == """{
    "status": "success"
}
"""

        response = requests.get(base_url + "/debug_web/empty_response")
        assert len(re.findall("\n", response.text)) == 1

    def test_other_error(self, core_system):
        response = requests.delete(base_url + "/debug_web/empty_response").json()
        assert response == {
            "status": "error",
            "error_id": "ERROR_GENERAL_METHOD_NOT_ALLOWED"
        }

    def test_other_error2(self, core_system):
        status_code_backup = copy.copy(core.plugin_base.module_dict['web'].base._status_code_to_error_id)
        core.plugin_base.module_dict['web'].base._status_code_to_error_id.clear()

        response = requests.delete(base_url + "/debug_web/empty_response").json()
        assert response == {
            'status': 'error',
            'error_id': 'ERROR_GENERAL_UNKNOWN'
        }

        core.plugin_base.module_dict['web'].base._status_code_to_error_id.update(status_code_backup)

    def test_thrown_exception(self, core_system):
        response = requests.get(base_url + "/debug_web/throw_exception").json()
        assert response == {
            "message": "Internal Server Error.",
            "error_id": "ERROR_GENERAL_INTERNAL",
            "status": "error"
        }

    def test_throw_custom_exception(self, core_system):
        response = requests.get(base_url + "/debug_web/throw_custom_exception").json()
        assert response == {
            'status': 'error',
            'error_id': 'ERROR_GENERAL_NOT_FOUND',
            'message': 'None',
            'test': True,
        }

    def test_ws_url_params(self, core_system):
        async def ws_worker():
            uri = ws_base_url + "/debug_web/ws_url_params?alpha=4"
            async with websockets.connect(uri) as websocket:
                response = await websocket.recv()
                assert json.loads(response) == {
                    "data": {
                        "alpha": 4,
                        "_pretty": []
                    },
                    "status": "success"
                }

            uri = ws_base_url + "/debug_web/ws_url_params"
            async with websockets.connect(uri) as websocket:
                response = await websocket.recv()
                assert json.loads(response) == {
                    "status": "error",
                    "path": ".alpha.0",
                    "error_id": "ERROR_GENERAL_FORMAT",
                    "section": "url_params",
                    "message": "This Value must be set."
                }

        asyncio.get_event_loop().run_until_complete(ws_worker())

    def test_ws_path_params(self, core_system):
        async def ws_worker():
            uri = ws_base_url + "/debug_web/ws_path_params/69/1.45"
            async with websockets.connect(uri) as websocket:
                response = await websocket.recv()
                assert json.loads(response) == {
                    "status": "success",
                    "data": [
                        69,
                        1.45
                    ]
                }

            uri = ws_base_url + "/debug_web/ws_path_params/4/f"
            async with websockets.connect(uri) as websocket:
                response = await websocket.recv()
                assert json.loads(response) == {
                    "message": "Can't convert \"f\" to float",
                    "section": "path_params",
                    "status": "error",
                    "error_id": "ERROR_GENERAL_FORMAT",
                    "path": ".1"
                }

        asyncio.get_event_loop().run_until_complete(ws_worker())

    def test_ws_message(self, core_system):
        async def ws_worker():
            uri = ws_base_url + "/debug_web/ws_message"
            async with websockets.connect(uri) as websocket:
                response = await websocket.recv()
                assert json.loads(response) == {
                    'status': 'success'
                }

                await websocket.send(json.dumps({
                    "charlie": "golf",
                }))
                response = await websocket.recv()
                assert json.loads(response) == {
                    "status": "success",
                    "data": {
                        "alpha": 5,
                        "charlie": "golf"
                    },
                    "delta": 45
                }

            uri = ws_base_url + "/debug_web/ws_message"
            async with websockets.connect(uri) as websocket:
                response = await websocket.recv()
                assert json.loads(response) == {
                    'status': 'success'
                }

                await websocket.send(json.dumps({}))
                response = await websocket.recv()
                assert json.loads(response) == {
                    "path": ".charlie",
                    "error_id": "ERROR_GENERAL_FORMAT",
                    "status": "error",
                    "section": "message_data",
                    "message": "This Value must be set."
                }

        asyncio.get_event_loop().run_until_complete(ws_worker())

    def test_ws_except_open(self, core_system):
        async def ws_worker():
            uri = ws_base_url + "/debug_web/ws_except1"
            async with websockets.connect(uri) as websocket:
                response = await websocket.recv()
                assert json.loads(response) == {
                    "status": "error",
                    "error_id": "ERROR_GENERAL_INTERNAL",
                    "message": "Internal Server Error."
                }

        asyncio.get_event_loop().run_until_complete(ws_worker())

    def test_ws_except_message(self, core_system):
        async def ws_worker():
            uri = ws_base_url + "/debug_web/ws_except2"
            async with websockets.connect(uri) as websocket:
                response = await websocket.recv()
                assert json.loads(response) == {
                    'status': 'success'
                }

                await websocket.send(json.dumps({}))
                response = await websocket.recv()
                assert json.loads(response) == {
                    "status": "error",
                    "error_id": "ERROR_GENERAL_INTERNAL",
                    "message": "Internal Server Error."
                }

        asyncio.get_event_loop().run_until_complete(ws_worker())


def test_ws_except_close(cs_bare, web_base_conf, capsys):
    cs_bare.conf = web_base_conf

    with cs_bare:
        async def ws_worker():
            uri = ws_base_url + "/debug_web/ws_except3"
            async with websockets.connect(uri) as websocket:
                response = await websocket.recv()
                assert json.loads(response) == {
                    'status': 'success'
                }

        asyncio.get_event_loop().run_until_complete(ws_worker())

    logs = capsys.readouterr().out
    print(logs)

    assert len(re.findall('[1-9][0-9]*' + ' ' + re.escape("error 500 ERROR_GENERAL_INTERNAL"), logs)) == 1
