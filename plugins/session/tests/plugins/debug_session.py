#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base
import core.casting

import datetime

plugin = core.plugin_base.PythapiPlugin("debug_session")
plugin.version = "1.0"
plugin.essential = False

plugin.depends = [
    {
        'name': 'session',
        'required': True
    }
]

plugin.config_defaults = {}


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/insecure_cookie",
    "method": "POST",
})
def test_set_insecure_cookie(request_obj, body_data, **kwargs):
    session = core.plugin_base.plugin_dict['session']
    session.set_cookie(request_obj, "TEST_COOKIE", body_data['data'], signed=False, encrypted=False)

    return {}


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/insecure_cookie",
    "method": "GET",
})
def test_set_insecure_cookie(request_obj, body_data, **kwargs):
    session = core.plugin_base.plugin_dict['session']
    data = session.get_cookie(request_obj, "TEST_COOKIE", signed=False, encrypted=False)

    return {
        "data": data
    }


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/signed_cookie",
    "method": "POST",
})
def test_set_signed_cookie(request_obj, body_data, **kwargs):
    session = core.plugin_base.plugin_dict['session']
    session.set_cookie(request_obj, "TEST_COOKIE", body_data['data'], signed=True, encrypted=False)

    return {}


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/signed_cookie",
    "method": "GET",
})
def test_set_signed_cookie(request_obj, body_data, **kwargs):
    session = core.plugin_base.plugin_dict['session']
    data = session.get_cookie(request_obj, "TEST_COOKIE", signed=True, encrypted=False)

    return {
        "data": data
    }


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/encrypted_cookie",
    "method": "POST",
})
def test_set_signed_cookie(request_obj, body_data, **kwargs):
    session = core.plugin_base.plugin_dict['session']
    session.set_cookie(request_obj, "TEST_COOKIE", body_data['data'], encrypted=True)

    return {}


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/encrypted_cookie",
    "method": "GET",
})
def test_set_signed_cookie(request_obj, body_data, **kwargs):
    session = core.plugin_base.plugin_dict['session']
    data = session.get_cookie(request_obj, "TEST_COOKIE", encrypted=True)

    return {
        "data": data
    }


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/expire_cookie",
    "method": "POST",
})
def test_set_insecure_cookie(request_obj, body_data, **kwargs):
    session = core.plugin_base.plugin_dict['session']
    session.set_cookie(request_obj,
                       "TEST_COOKIE",
                       body_data['data'],
                       signed=True,
                       encrypted=False,
                       expires=datetime.datetime.strptime(body_data['expires'], '%Y-%m-%dT%H:%M:%SZ'))

    return {}


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/session",
    "method": "POST",
})
def test_create_session(request_obj, body_data, **kwargs):
    session = core.plugin_base.plugin_dict['session']
    session.create_session(request_obj,
                           reset=body_data.get('reset', False))


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/session_time",
    "method": "POST",
})
def test_create_session_time(request_obj, body_data, **kwargs):
    session = core.plugin_base.plugin_dict['session']
    session.create_session(request_obj,
                           reset=body_data.get('reset', None),
                           expires=datetime.datetime.strptime(body_data.get('expires', None),
                                                              '%Y-%m-%dT%H:%M:%SZ'))


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/session_timedelta",
    "method": "POST",
})
def test_create_session_timedelta(request_obj, body_data, **kwargs):
    session = core.plugin_base.plugin_dict['session']
    session.create_session(request_obj,
                           reset=body_data.get('reset', None),
                           expires=body_data.get('expires', None))


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/session",
    "method": "PUT",
})
def test_edit_session(session, body_data, **kwargs):
    session.update(body_data['data'])


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/session",
    "method": "GET",
})
def test_edit_session(session, **kwargs):
    return {
        "data": session
    }


@core.plugin_base.event(plugin, 'web.request', {
    "path": "/session",
    "method": "DELETE",
})
def test_destroy_session(request_obj, **kwargs):
    session = core.plugin_base.plugin_dict['session']
    session.destroy_session(request_obj)
