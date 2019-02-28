#
# Name:        pythapi: unittests
# Author:      Rene Fa
# Date:        28.02.2019
# Version:     0.1
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

import pytest
import importlib

import argparse

def start_pythapi(**kwargs):

    pythapi = importlib.reload(importlib.import_module('pythapi'))

    args = argparse.Namespace()
    args.config = kwargs.get('config', None)
    args.config_data = kwargs.get('config_data', [])
    args.force = kwargs.get('force', False)
    args.mode = kwargs.get('mode', 'run')
    args.no_fancy = kwargs.get('no_fancy', False)
    args.plugin = kwargs.get('plugin', '')
    args.reinstall = kwargs.get('reinstall', False)
    args.verbosity = kwargs.get('verbosity', None)
    args.debug_override_config = kwargs.get('debug_override_config', None)

    pythapi.main(args, skip_loop=True)

    return pythapi
