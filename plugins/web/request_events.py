#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base
import core.casting

from . import header
from . import base

import copy


def _path_and_url_arg_handling(match_data, data, robj):
    # Url-arg handling
    path_params = dict(zip(data['_path_param_names'], list(match_data.groups())))
    try:
        ua_skel = copy.copy(data['path_params'])
        ua_skel['template'] = {
            "type": dict,
            "verify": False,
        }

        path_params = core.casting.reinterpret(path_params, **ua_skel)
    except core.casting.CastingException as e:
        e.data['section'] = 'path_params'
        raise e

    # Get-Param handling
    try:
        gp_skel = copy.copy(data['url_params'])
        gp_skel['template'] = {
            "type": dict,
            "verify": True,
        }

        if data['content_type'] == "application/json":
            gp_skel['template']['child'] = {
                "_pretty": {
                    "type": list,
                    "single_cast_mode": 2,
                    "children": {
                        "type": bool,
                        "default": False
                    },
                    "default": []
                }
            }

        url_params = core.casting.reinterpret(robj.request.arguments, **gp_skel)
    except core.casting.CastingException as e:
        e.data['section'] = 'url_params'
        raise e

    return path_params, url_params


@core.plugin_base.event(header.plugin, 'web.pre_request', {
    "priority": 0
})
def _base_pre_event_request(env, event_data):
    match_data = env['match_data']
    data = env['request_settings']
    robj = env['request_obj']

    # Set Header
    for k, v in core.plugin_base.config[header.plugin.name]['additional_headers'].items():
        robj.set_header(k, v)

    path_params, url_params = _path_and_url_arg_handling(match_data, data, robj)

    # Body data handling
    body_data = robj.request.body
    if data['request_content_type'] == 'application/json':
        body_data = body_data.decode('utf8')

        try:
            bd_skel = copy.copy(data['body_data'])
            bd_skel['template'] = {
                "type": dict,
                "convert": False,
                "verify": True,
            }

            body_data = core.casting.reinterpret(body_data, **{
                "type": dict,
                "pipe": [bd_skel]
            })
        except core.casting.CastingException as e:
            e.data['section'] = 'body_data'
            raise e

    env['path_params'] = path_params
    env['url_params'] = url_params
    env['body_data'] = body_data


@core.plugin_base.event(header.plugin, 'web.socket.pre_open', {
    "priority": 0
})
def _base_pre_event_socket_open(env, event_data):
    match_data = env['match_data']
    data = env['request_settings']
    robj = env['request_obj']

    path_params, url_params = _path_and_url_arg_handling(match_data, data, robj)

    env['path_params'] = path_params
    env['url_params'] = url_params


@core.plugin_base.event(header.plugin, 'web.socket.pre_message', {
    "priority": 0
})
def _base_pre_event_socket_message(env, event_data):
    data = env['request_settings']
    message_data = env['message_data']

    # Body data handling
    if data['input_message_content_type'] == 'application/json':
        try:
            bd_skel = copy.copy(data['input_message_format'])
            bd_skel['template'] = {
                "type": dict,
                "convert": False,
                "verify": True,
            }

            message_data = core.casting.reinterpret(message_data, **{
                "type": dict,
                "pipe": [bd_skel]
            })
        except core.casting.CastingException as e:
            e.data['section'] = 'message_data'
            raise e

    env['message_data'] = message_data


@core.plugin_base.event(header.plugin, 'web.socket.post_message', {
    "priority": 5,
})
@core.plugin_base.event(header.plugin, 'web.post_request', {
    "priority": 5,
})
def _format_response(env, event_data):
    env['response'] = base.format_message(env, env['response'])


@core.plugin_base.event(header.plugin, 'web.post_request', {
    "priority": 0
})
def _send_response_request(env, event_data):
    data = env['request_settings']
    response = env['response']
    robj = env['request_obj']

    robj.set_header('Server', "pythapi/{}".format(core.plugin_base.version))
    robj.set_header('Content-Type', data['content_type'])
    robj.write(response)


@core.plugin_base.event(header.plugin, 'web.socket.post_message', {
    "priority": 0
})
def _send_response_socket(env, event_data):
    response = env['response']
    robj = env['request_obj']

    if response is not None:
        robj.write_message(response.encode('utf8'))
