#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi
# Author:      Rene Fa
# Date:        10.07.2018
version = 2.0
#
# Description: This is a RESTful API WebServer with focus on extensibility.
#              It's target is to make it possible to easily build your own API.
#
# Copyright:   Copyright (C) 2018  Rene Fa
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

import signal, sys, os
import configparser, argparse
import glob

import tornado.web
import tornado.httpserver
import tornado.ioloop
from tornado import gen

from . import fancy_logs
from . import defaults

class MyHandler(tornado.web.RequestHandler):

    @gen.coroutine
    def get(self):
        self.write('before')
        yield gen.sleep(5)
        self.write('after')
        self.finish()

def terminate_application():
    log.info("Pythapi terminated.")
    sys.exit(0)

def termination_handler(signal, frame):
    print()
    terminate_application()

def run(args, test_mode=False):
    global log

    # Initialize fancy_logs
    log = fancy_logs.fancy_logger(
    	True,
        6,
        False,
        'pythapilog_nope.txt'
    )

    log.debug("Hallo Welt!")
