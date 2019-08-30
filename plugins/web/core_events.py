#!/usr/bin/python3
# -*- coding: utf-8 -*-

import core.plugin_base
import core.casting

from . import header
from . import base

import tornado.escape
import tornado.web
import tornado.websocket
import tornado.httpserver
import tornado.ioloop
import tornado.platform.asyncio
import tornado.concurrent

import logging
import os

servers = []


@core.plugin_base.external_function(header.plugin)
def start():

    # TODO: Websocket ready machen
    # TODO: Router benutzen
    # TODO: Base URL für API
    # TODO: Static Webserver

    core.plugin_base.log.info("Starting HTTP servers...")
    core.plugin_base.log.indent(1)
    for item in core.plugin_base.config[header.plugin.name]['binds']:
        # core.plugin_base.log.debug(core.casting.reinterpret(item, str, pretty=True, sort_keys=True))

        if item['api_only']:
            app = tornado.web.Application([(r"/.*?", base.APIBase)])
        else:
            if not item['static_root']:
                raise core.casting.MissingValueError(None, "Static root directory not defined!")

            if not os.path.isdir(item['static_root']):
                raise core.casting.MissingValueError(None, "Static root directory not found!")

            app = tornado.web.Application([
                #(r"/ws", EchoWebSocket),
                (r"/.*?", base.APIBase),
            ])

        if not item['ssl']:
            srv = tornado.httpserver.HTTPServer(app)
        else:

            for file in ["cert", "key"]:
                if item[file + '_file'] is None:
                    raise core.casting.MissingValueError(None, file + "file not defined!")

                if not os.path.isfile(item['key_file']):
                    raise core.casting.MissingValueError(None, file + "file not found!")

            srv = tornado.httpserver.HTTPServer(app, ssl_options={
                "certfile": item['cert_file'],
                "keyfile": item['key_file']
            })

        servers.append(srv)
        srv.bind(item['port'], item['ip'])
        srv.start()

        core.plugin_base.log.debug("Opened port at: {}:{}, ssl: {}, api_only: {}".format(item['ip'],
                                                                        item['port'],
                                                                        item['ssl'],
                                                                        item['api_only']
                                                                        ))

    core.plugin_base.log.indent(-1)


@core.plugin_base.external_function(header.plugin)
def stop():
    for srv in servers:
        srv.stop()

    core.plugin_base.log.info("Webservers terminated.")


@core.plugin_base.event(header.plugin, 'core.load', {})
def load():
    global servers
    servers = []

    event_pre_sort_list_1 = {}
    event_post_sort_list_1 = {}
    for plugin_name in core.plugin_base.serialized_plugin_list:
        # Building index and initialize values for request handlers
        for f, data in core.plugin_base.plugin_dict[plugin_name].events.get('web.request', []):
            data = core.casting.reinterpret(data, d_plugin_name=plugin_name, **header.web_request_data_skeleton)

            header.request_event_list[data['method']].append((data["_c_regex"], f, data))

        for f, data in core.plugin_base.plugin_dict[plugin_name].events.get('web.pre_request', []):
            if data['priority'] not in event_pre_sort_list_1:
                event_pre_sort_list_1[data['priority']] = []

            event_pre_sort_list_1[data['priority']].append((f, data,))

        for f, data in core.plugin_base.plugin_dict[plugin_name].events.get('web.post_request', []):
            if data['priority'] not in event_post_sort_list_1:
                event_post_sort_list_1[data['priority']] = []

            event_post_sort_list_1[data['priority']].append((f, data,))

    # Brings the pre and post event_handler in the right order
    event_pre_sort_list_2 = sorted(event_pre_sort_list_1.items())
    event_post_sort_list_2 = sorted(event_post_sort_list_1.items())

    for p_items in event_pre_sort_list_2:
        header.pre_request_event_list.extend(p_items[1])

    for p_items in event_post_sort_list_2:
        header.post_request_event_list.extend(p_items[1])

    # Disable messages from Tornado
    hn = logging.NullHandler()
    hn.setLevel(logging.DEBUG)
    logging.getLogger("tornado.access").addHandler(hn)
    logging.getLogger("tornado.access").propagate = False

    logging.getLogger("tornado.application").addHandler(hn)
    logging.getLogger("tornado.application").propagate = False

    tornado.platform.asyncio.AsyncIOMainLoop().install()
    start()


@core.plugin_base.event(header.plugin, 'core.terminate')
def terminate():
    stop()
