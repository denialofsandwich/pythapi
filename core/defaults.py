#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi
# Author:      Rene Fa
# Date:        01.04.2019
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

config_defaults = {
    "core.general": {
        "loglevel": {"type": int, "default": 5},
        "colored_logs": {"type": bool, "default": True},
        "file_logging_enabled": {"type": bool, "default": True},
        "logfile": {"type": str, "default": "pythapilog_[time].log"},
        "user": {"type": str, "default": "root"},
    }
}

config_base_path = "pythapi.ini"
