#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi
# Author:      Rene Fa
# Date:        06.04.2019
#
# Copyright:   Copyright (C) 2019  Rene Fa
#
#              This program is free software: you can redistribute it and/or modify
#              it under the terms of the GNU Affero General Public License as published by
#              the Free Software Foundation, either version 3 of the License, or any later version.
#
#              This program is distributed in the hope that it will be useful,
#              but WITHOUT ANY WARRANTY; without even the implied warranty of
#              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#              GNU Affero General Public License for more details.
#
#              You should have received a copy of the GNU Affero General Public License
#              along with this program.  If not, see https://www.gnu.org/licenses/agpl-3.0.de.html.
#

import tornado.web
import tornado.httpserver
from tornado import gen


class MyHandler(tornado.web.RequestHandler):
    @gen.coroutine
    def get(self):
        self.write("before")
        yield gen.sleep(5)
        self.write("after")
        self.finish()


def terminate():
    if http_server:
        log.debug("HTTP-Server terminated.")
        http_server.stop()

    log.info("Webservers terminated.")


def start(config, p_log):
    global log
    global http_server
    global https_server

    log = p_log

    app = tornado.web.Application([(r"/", MyHandler)])

    http_server = tornado.httpserver.HTTPServer(app)
    http_server.bind(8888)
    http_server.start()
