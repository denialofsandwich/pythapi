#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base
import core.casting

from . import header
from . import base

import tornado.escape
import tornado.web
import tornado.httpserver
import tornado.ioloop
import tornado.platform.asyncio
import tornado.concurrent

import logging
import os
import copy

servers = []
ws_re_list = []

# TODO: Vielleicht ändere ich die "path" Syntax von /user/* zu /user/{user_name}
#   => Ein Dict statt List bei path_params
#   - Ich stelle mir das deutlich leserlicher vor. Und so lässt es sich auch einfacher dokumentieren.


def _set_base_url(prefix='', static_web_server=False):
    tmp_re_list = copy.deepcopy(ws_re_list)
    for i, regex in enumerate(tmp_re_list):
        for j, rp in enumerate(regex):
            tmp_re_list[i][j] = rp.replace('(', '').replace(')', '')

        tmp_re_list[i] = prefix.join(tmp_re_list[i])

    ws_regex = r'(?:' + r')|(?:'.join(tmp_re_list) + r')'

    if static_web_server:
        api_regex = r"" + prefix + r"/.*"
    else:
        api_regex = r"/.*"

    return ws_regex, api_regex


@core.plugin_base.external(header.plugin)
def start():
    core.plugin_base.log.info("Starting HTTP servers...")
    core.plugin_base.log.indent(1)
    for item in core.plugin_base.config[header.plugin.name]['binds']:

        if item['static_web_server']:
            if not item['static_root']:
                core.plugin_base.log.error("Static root directory not defined!")
                raise core.casting.MissingValueError(None, "Static root directory not defined!")

            if not os.path.isdir(item['static_root']):
                core.plugin_base.log.error("Static root directory not found!")
                raise core.casting.MissingValueError(None, "Static root directory not found!")

            header.request_prefix_table[str(item['port'])] = item['api_base_url']
            ws_regex, api_regex = _set_base_url(item['api_base_url'], item['static_web_server'])

            CustomSMPH = type('CustomSMPH',
                              base.ServeMainPageHandler.__bases__,
                              dict(base.ServeMainPageHandler.__dict__))
            CustomSMPH.base_dir = item['static_root']

            app = tornado.web.Application([
                (ws_regex, base.WebSocketBase),
                (api_regex, base.APIBase),
                (r"/([^.]*)", CustomSMPH),
                (r"/(.*)", tornado.web.StaticFileHandler,
                    {
                        "path": item['static_root'],
                        "default_filename": "index.html"
                    })
            ])
        else:
            header.request_prefix_table[str(item['port'])] = item['api_base_url']
            ws_regex, api_regex = _set_base_url(item['api_base_url'], item['static_web_server'])

            app = tornado.web.Application([
                (ws_regex, base.WebSocketBase),
                (api_regex, base.APIBase),
            ])

        if not item['ssl']:
            srv = tornado.httpserver.HTTPServer(app)
        else:
            for file in ["cert", "key"]:
                if item[file + '_file'] is None:
                    core.plugin_base.log.error(file + "file not defined!")
                    raise core.casting.MissingValueError(None, file + "file not defined!")

                if not os.path.isfile(item[file + '_file']):
                    core.plugin_base.log.error(file + "file not found!")
                    raise core.casting.MissingValueError(None, file + "file not found!")

            srv = tornado.httpserver.HTTPServer(app, ssl_options={
                "certfile": item['cert_file'],
                "keyfile": item['key_file']
            })

        servers.append(srv)
        srv.bind(item['port'], item['ip'])
        srv.start()

        core.plugin_base.log.debug("Opened port at: {}:{}, ssl: {}, static_web_server: {}".format(item['ip'],
                                   item['port'],
                                   item['ssl'],
                                   item['static_web_server']
                                   ))

    core.plugin_base.log.indent(-1)


@core.plugin_base.external(header.plugin)
def stop():
    for srv in servers:
        srv.stop()

    core.plugin_base.log.info("Webservers terminated.")


@core.plugin_base.event(header.plugin, 'core.load', {})
def load():
    global servers
    global ws_re_list
    servers = []

    header.request_event_list = {}
    header.websocket_event_list = []
    header.plugin.request_name_table = {}

    header.pre_request_event_list = []
    header.post_request_event_list = []
    header.websocket_pre_open_event_list = []
    header.websocket_pre_message_event_list = []
    header.websocket_post_message_event_list = []
    header.websocket_close_event_list = []

    header.request_prefix_table = {}

    ws_re_list = []
    supported_methods_set = set()
    event_sort_lists = [
        ('web.pre_request', header.pre_request_event_list, {}),
        ('web.post_request', header.post_request_event_list, {}),
        ('web.socket.pre_open', header.websocket_pre_open_event_list, {}),
        ('web.socket.pre_message', header.websocket_pre_message_event_list, {}),
        ('web.socket.post_message', header.websocket_post_message_event_list, {}),
        ('web.socket.close', header.websocket_close_event_list, {}),
    ]
    for plugin_name in core.plugin_base.serialized_plugin_list:
        header.plugin.request_name_table[plugin_name] = {}

        # This is necessary, to keep the static event support
        core.plugin_base.plugin_dict[plugin_name].events['_BAK_web.request'] = \
            list(core.plugin_base.plugin_dict[plugin_name].events.get('web.request', []))
        core.plugin_base.plugin_dict[plugin_name].events['_BAK_web.socket'] = \
            list(core.plugin_base.plugin_dict[plugin_name].events.get('web.socket', []))

        for f, data in core.plugin_base.plugin_dict[plugin_name].events.get('web.init', []):
            f(data)

        # Building index and initialize values for request handlers
        for f, data in core.plugin_base.plugin_dict[plugin_name].events.get('web.request', []):
            data.update(core.casting.reinterpret(data, d_plugin_name=plugin_name, **header.web_request_data_skeleton))

            header.plugin.request_name_table[plugin_name][data['name']] = data

            if data["_c_regex"] not in header.request_event_list:
                header.request_event_list[data["_c_regex"]] = {}

            if header.request_event_list[data["_c_regex"]].get(data['method'], None):
                core.plugin_base.log.warning("Ambiguous path found: {}".format(data.get("regex", None)))

            header.request_event_list[data["_c_regex"]][data['method']] = (f, data)
            supported_methods_set.add(data['method'])

        for c, data in core.plugin_base.plugin_dict[plugin_name].events.get('web.socket', []):
            data.update(core.casting.reinterpret(data, d_plugin_name=plugin_name, **header.web_socket_data_skeleton))

            header.plugin.request_name_table[plugin_name][data['name']] = data

            ws_re_list.append(data["_raw_regex"])
            header.websocket_event_list.append((data["_c_regex"], c, data))

        for event_name, event_list, event_dict in event_sort_lists:
            for f, data in list(core.plugin_base.plugin_dict[plugin_name].events.get(event_name, [])):
                data = core.casting.reinterpret(data, **header.pre_post_event_data_skeleton)

                if data['priority'] not in event_dict:
                    event_dict[data['priority']] = []

                event_dict[data['priority']].append((f, data))

    base.APIBase.SUPPORTED_METHODS = tuple(supported_methods_set)
    for method in supported_methods_set:
        setattr(base.APIBase, method.lower(), base.APIBase.method_tpl)

    # To bring the pre and post event_handler in the right order
    for event_name, event_list, event_dict in event_sort_lists:
        event_list.clear()
        event_list.extend(sorted(list(event_dict.items())))

        tmp_list = list(event_list)
        event_list.clear()

        for p_items in list(tmp_list):
            event_list.extend(p_items[1])

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
    # Remove all dynamically generated events
    for plugin_name in core.plugin_base.serialized_plugin_list:
        core.plugin_base.plugin_dict[plugin_name].events['web.request'] = \
            core.plugin_base.plugin_dict[plugin_name].events.get('_BAK_web.request', [])
        core.plugin_base.plugin_dict[plugin_name].events['web.socket'] = \
            core.plugin_base.plugin_dict[plugin_name].events.get('_BAK_web.socket', [])

    stop()
