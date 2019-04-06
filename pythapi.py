#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi
# Author:      Rene Fa
# Date:        01.04.2019
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

import signal
import argparse

import core.main

if __name__ == "__main__":
    signal.signal(signal.SIGINT, core.main.termination_handler)
    signal.signal(signal.SIGTERM, core.main.termination_handler)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        default="run",
        nargs="?",
        choices=["run", "install", "uninstall"],
        help="Specifies the run-mode",
    )
    parser.add_argument(
        "plugin", default="", nargs="?", help="Specify a plugin to install/uninstall"
    )
    parser.add_argument("--verbosity", "-v", type=int, help="Sets the verbosity")
    parser.add_argument(
        "--reinstall",
        "-r",
        action="store_true",
        help="Uninstalls a plugin before installing it",
    )
    parser.add_argument(
        "--force", "-f", action="store_true", help="Force an instruction to execute"
    )
    parser.add_argument(
        "--no-fancy",
        "-n",
        action="store_true",
        help="Disables the colorful logs and shows a more machine-readable logging format",
    )
    parser.add_argument(
        "--config-data",
        "-d",
        default=[],
        action="append",
        help="Add config-parameter eg. (core.web.http_port=8123)",
    )
    parser.add_argument("--config", "-c", help="Add config-file")
    parser.add_argument("--debug-override-config", help="Just for debugging purposes")

    args = parser.parse_args()

    core.main.run(args)
