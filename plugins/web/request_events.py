#!/usr/bin/python3
# -*- coding: utf-8 -*-

import core.plugin_base
import core.casting
from . import header

import tornado.escape
import tornado.concurrent

import copy


@core.plugin_base.event(header.plugin, 'web.post_request', {
    "priority": 4
})
def debug_print(env, event_data):
    #core.plugin_base.log.debug(env)
    pass


@core.plugin_base.event(header.plugin, 'web.pre_request', {
    "priority": 0
})
def _base_pre_event(env, event_data):
    match_data = env['match_data']
    data = env['request_settings']
    robj = env['request_obj']

    # Set Header
    for k, v in core.plugin_base.config[header.plugin.name]['additional_headers'].items():
        robj.set_header(k, v)

    # Url-arg handling
    path_params = list(match_data.groups())
    try:
        ua_skel = copy.copy(data['path_params'])
        ua_skel['template'] = {
            "type": list,
            "verify": True,
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

        url_params = core.casting.reinterpret(robj.request.arguments, **gp_skel)
    except core.casting.CastingException as e:
        e.data['section'] = 'url_params'
        raise e

    # Body data handling
    body_data = robj.request.body
    if data['request_content_type'] == 'application/json':
        body_data = body_data.decode('utf8')

        if body_data == "":
            body_data = {}
        else:
            try:
                body_data = tornado.escape.json_decode(body_data)
            except ValueError:
                # TODO: Exception!
                core.plugin_base.log.error("JSON Syntax Error")
                return

        try:
            bd_skel = copy.copy(data['body_data'])
            bd_skel['template'] = {
                "type": dict,
                "convert": False,
                "verify": True,
            }

            body_data = core.casting.reinterpret(body_data, **bd_skel)
        except core.casting.CastingException as e:
            e.data['section'] = 'body_data'
            raise e

    env['path_params'] = path_params
    env['url_params'] = url_params
    env['body_data'] = body_data


@core.plugin_base.event(header.plugin, 'web.post_request', {
    "priority": 5
})
def _format_response(env, event_data):
    data = env['request_settings']
    response = env['response']

    if data['content_type'] == "application/json":
        if "status" not in response:
            response['status'] = "success"

        response = core.casting.reinterpret(response, str, **{
            "template": data['response_format'],
            "type": dict,
            "type_defaults": {
                "*": {
                    "type": str,
                }
            }
        }) + '\n'

        env['response'] = response


@core.plugin_base.event(header.plugin, 'web.post_request', {
    "priority": 0
})
def _send_response(env, event_data):
    data = env['request_settings']
    response = env['response']
    robj = env['request_obj']

    robj.set_header('Server', "pythapi/{}".format(core.plugin_base.version))
    robj.set_header('Content-Type', data['content_type'])
    robj.write(response)
