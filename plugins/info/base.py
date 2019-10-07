#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base


def get_plugin_info(plugin_name):
    p = core.plugin_base.plugin_dict[plugin_name]

    return {
        "plugin_name": p.name,
        "version": p.version,
        "info": p.info,
        "depends": p.depends,
        "events": p.events,
    }


def get_request_info(plugin_name, request_name):
    web = core.plugin_base.plugin_dict['web']
    req = dict(web.request_name_table[plugin_name][request_name])

    return req
