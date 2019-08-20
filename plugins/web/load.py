#!/usr/bin/python3
# -*- coding: utf-8 -*-

import core.plugin_base
import core.casting
from . import header

import tornado.web
import tornado.httpserver
import tornado.ioloop
import tornado.platform.asyncio
from tornado import gen

log = None
config = None

http_server = None
https_server = None


class WebServerBase(tornado.web.RequestHandler):
    @gen.coroutine
    def _handle_request(self):
        # TODO: Inputs wie Post body, params und args
        # TODO: Custom Header
        # TODO: 404 Handler
        # TODO: Custom Methods
        method = self.request.method
        uri = self.request.uri
        for action in header.request_list[method]:
            if action[0].match(uri):
                action[1]()

    @gen.coroutine
    def get(self, **kwargs):
        yield self._handle_request()

    @gen.coroutine
    def post(self, **kwargs):
        yield self._handle_request()

    @gen.coroutine
    def put(self, **kwargs):
        yield self._handle_request()

    @gen.coroutine
    def delete(self, **kwargs):
        yield self._handle_request()


@core.plugin_base.external_function(header.plugin)
def start():
    global http_server
    global https_server

    # TODO: Websocket ready machen
    #   - Router benutzen
    #   - Base URL für API
    #   - Static Webserver
    app = tornado.web.Application([(r"/.*?", WebServerBase)])

    http_binds = core.plugin_base.config[header.plugin.name]['http_binds']
    if len(http_binds) > 0:
        http_server = tornado.httpserver.HTTPServer(app)
        for ip, port in http_binds:
            port = int(port)
            http_server.bind(port, ip)
            log.debug("Opening HTTP port at: {}:{}".format(ip, port))

        http_server.start()
        log.info("HTTP Server started")

    # TODO: HTTPS Server


@core.plugin_base.external_function(header.plugin)
def stop():
    if http_server:
        log.debug("HTTP-Server terminated.")
        http_server.stop()

    log.info("Webservers terminated.")


@core.plugin_base.external_function(header.plugin)
def test_external_function(msg):
    log.debug(msg)


@core.plugin_base.event(header.plugin, 'core.load')
def load():
    global log
    log = core.plugin_base.log

    for plugin_name in core.plugin_base.serialized_plugin_list:
        for f, data in core.plugin_base.plugin_dict[plugin_name].events.get('web.request', []):
            data = core.casting.reinterpret(data, d_plugin_name=plugin_name, **header.web_request_data_skeleton)
            header.request_list[data.get('method', 'GET')].append((data["c_regex"], f, data))

    tornado.platform.asyncio.AsyncIOMainLoop().install()
    start()


@core.plugin_base.event(header.plugin, 'core.terminate')
def terminate():
    stop()
