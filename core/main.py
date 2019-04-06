#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi
# Author:      Rene Fa
# Date:        02.04.2019
version = 2.0
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

import signal, sys, os
import glob

import tornado.ioloop

from . import fancy_logs
from . import parse_conf
from . import defaults
from . import webserver


def terminate_application():
    webserver.terminate()
    log.info("Pythapi terminated.")
    sys.exit(0)


def termination_handler(signal, frame):
    print()
    terminate_application()


def run(args, test_mode=False):
    global log

    # Read configuration files
    config_parser = parse_conf.PythapiConfigParser()
    config_parser.read_defaults(defaults.config_defaults)  # Core defaults only
    config_parser.recursive_read(defaults.config_base_path)

    config_cgen = config_parser.as_dict()["core.general"]

    # Initialize fancy_logs
    # TODO: Indentation if fancy=true
    log = fancy_logs.fancy_logger(
        config_cgen["colored_logs"],
        config_cgen["loglevel"],
        config_cgen["file_logging_enabled"],
        config_cgen["logfile"],
    )

    # Initialize and load Plugins
    # TODO: Initialize and load Plugins

    # Initialize the Tornado Webservers
    webserver.start(config_parser.as_dict()["core.web"], log)
    log.success("pythapi successfully started.")

    log.info("Entering main loop...")
    tornado.ioloop.IOLoop.current().start()
