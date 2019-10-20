#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base
from . import header
from . import base


@core.plugin_base.event(header.plugin, 'web.init')
def web_init(event_data):
    web = core.plugin_base.plugin_dict['web']

    @core.plugin_base.external(header.plugin)
    class PluginNotFoundException(web.WebRequestException):
        def __init__(self, plugin_name, **kwargs):
            web.WebRequestException.__init__(self,
                                             error_id='ERROR_PLUGIN_NOT_FOUND',
                                             status_code=400,
                                             message={
                                                 "_tr": True,
                                                 "EN": "Plugin \"{}\" does not exist.".format(plugin_name),
                                                 "DE": "Plugin \"{}\" existiert nicht.".format(plugin_name)
                                             }, data={
                                                  "plugin_name": plugin_name
                                             }, **kwargs)

    @core.plugin_base.external(header.plugin)
    class RequestNotFoundException(web.WebRequestException):
        def __init__(self, request_name, **kwargs):
            web.WebRequestException.__init__(self,
                                             error_id='ERROR_REQUEST_NOT_FOUND',
                                             status_code=400,
                                             message={
                                                 "_tr": True,
                                                 "EN": "Request \"{}\" does not exist.".format(request_name),
                                                 "DE": "Request \"{}\" existiert nicht.".format(request_name)
                                             }, data={
                                                  "request_name": request_name
                                             }, **kwargs)

    @core.plugin_base.event(header.plugin, 'web.request', {
        "path": "/plugin/list",
        "method": "GET",
        'f_name': {
            '_tr': True,
            'EN': 'List plugins',
            'DE': 'Liste Plugins auf',
        },
        'f_description': {
            '_tr': True,
            'EN': 'Returns a list of all active Plugins.',
            'DE': 'Gibt eine Liste mit allen aktiven Plugins zurück.',
        },
        "url_params": {
            "child": {
                "verbose": web.web_template_table['verbose'],
            }
        },
        "output_message_format": {
            "inheritable_parameters": [
                "pre_format",
                "env"
            ],
            "pre_format": web.format_tr_table,
        },
    })
    def list_plugins(url_params, **kwargs):
        if url_params['verbose']:
            data = {}
            for plugin_name in core.plugin_base.plugin_dict.keys():
                data[plugin_name] = base.get_plugin_info(plugin_name)
        else:
            data = list(core.plugin_base.plugin_dict.keys())

        return {
            "data": data,
        }

    @core.plugin_base.event(header.plugin, 'web.request', {
        "path": "/plugin/name/{plugin_name}",
        "method": "GET",
        'f_name': {
            '_tr': True,
            'EN': 'Get plugin',
            'DE': 'Zeige Plugin',
        },
        'f_description': {
            '_tr': True,
            'EN': 'Returns information about a single plugin.',
            'DE': 'Gibt Informationen über ein einzelnes Plugin zurück.',
        },
        "path_params": {
            "child": {
                "plugin_name": header.plugin.web_template_table['plugin_name'],
            }
        },
        "output_message_format": {
            "inheritable_parameters": [
                "pre_format",
                "env"
            ],
            "pre_format": web.format_tr_table,
        },
    })
    def get_plugin(path_params, **kwargs):
        return {
            "data": base.get_plugin_info(path_params['plugin_name']),
        }

    @core.plugin_base.event(header.plugin, 'web.request', {
        "path": "/request/{plugin_name}/list",
        "method": "GET",
        'f_name': {
            '_tr': True,
            'EN': 'List requests',
            'DE': 'Liste Requests auf',
        },
        'f_description': {
            '_tr': True,
            'EN': 'Returns a list with all requests of a plugin.',
            'DE': 'Gibt eine Liste mit allen Requests eines Plugins zurück.',
        },
        "path_params": {
            "child": {
                "plugin_name": header.plugin.web_template_table['plugin_name'],
            }
        },
        "url_params": {
            "child": {
                "verbose": web.web_template_table['verbose'],
            }
        },
        "output_message_format": {
            "inheritable_parameters": [
                "pre_format",
                "env"
            ],
            "pre_format": web.format_tr_table,
        },
    })
    def list_requests_of_plugin(path_params, url_params, **kwargs):
        plugin_name = path_params['plugin_name']

        if url_params['verbose']:
            data = {}
            for request_name in web.request_name_table[plugin_name].keys():
                data[request_name] = base.get_request_info(plugin_name, request_name)
        else:
            data = list(web.request_name_table[plugin_name].keys())

        return {
            "data": data,
        }

    @core.plugin_base.event(header.plugin, 'web.request', {
        "path": "/request/{plugin_name}/name/{request_name}",
        "method": "GET",
        'f_name': {
            '_tr': True,
            'EN': 'Get Request',
            'DE': 'Zeige Request',
        },
        'f_description': {
            '_tr': True,
            'EN': 'Returns information from a single Request.',
            'DE': 'Gibt Informationen über einen einzelnen Request zurück.',
        },
        "path_params": {
            "child": {
                "plugin_name": header.plugin.web_template_table['plugin_name'],
                "request_name": header.plugin.web_template_table['request_name'],
            }
        },
        "output_message_format": {
            "inheritable_parameters": [
                "pre_format",
                "env"
            ],
            "pre_format": web.format_tr_table,
        },
    })
    def get_request_of_plugin(path_params, **kwargs):
        return {
            "data": base.get_request_info(path_params['plugin_name'], path_params['request_name']),
        }
