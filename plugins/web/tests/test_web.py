#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest

import plugins.web

import argparse
import threading
import asyncio
import re
import collections

# TODO: Create Tests

# import tornado.web
# import tornado.httpserver
# from tornado import gen
#
#
# class MyHandler(tornado.web.RequestHandler):
#     @gen.coroutine
#     def get(self):
#         self.write("before")
#         yield gen.sleep(5)
#         self.write("after")
#         self.finish()
#
#
# def terminate():
#     if http_server:
#         log.debug("HTTP-Server terminated.")
#         http_server.stop()
#
#     log.info("Webservers terminated.")
#
#
# def start(config, p_log):
#     global log
#     global http_server
#     global https_server
#
#     log = p_log
#
#     app = tornado.web.Application([(r"/", MyHandler)])
#
#     http_server = tornado.httpserver.HTTPServer(app)
#     ip_address = config['bind_ip']
#     for port in config['http_port']:
#         http_server.bind(port, ip_address)
#         log.debug("HTTP started at: {}:{}".format(ip_address, port))
#
#     http_server.start()
