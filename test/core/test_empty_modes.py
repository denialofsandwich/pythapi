#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: unittests
# Author:      Rene Fa
# Date:        08.02.2019
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
#
# Usage:       PYTHONPATH=. pytest --cov .
#       Use in project root directory
#
# Requires:    pytest coverage pytest-cov
#

import pytest
import importlib

import pythapi
import argparse

def test_startup():

    pythapi = importlib.reload(importlib.import_module('pythapi'))

    args = argparse.Namespace()
    args.config = None
    args.config_data = []
    args.force = False
    args.mode = 'run'
    args.no_fancy = False
    args.plugin = ''
    args.reinstall = False
    args.verbosity = None
    args.debug_override_config = "test/core/configs/base_conf.ini"

    pythapi.main(args, skip_loop=True)

    with pytest.raises(SystemExit) as pytest_wrapped_e:
        pythapi.terminate_application()

    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 0
    assert 1 == 0


