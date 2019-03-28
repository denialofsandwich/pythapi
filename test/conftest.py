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

import argparse
import test.tools.pythapi_testing_tools as ptt

@pytest.fixture(scope="session")
def pythapi(request):
    global pythapi_instance
    pythapi_instance = ptt.start_pythapi(
        debug_override_config="test/base_conf.ini",
    )

    yield pythapi_instance

    with pytest.raises(SystemExit) as pytest_wrapped_e:
        pythapi_instance.terminate_application()

@pytest.fixture(scope="function")
def sqldb(request):

    db = pythapi_instance.api_plugin.api_mysql_connect()
    db.prefix = pythapi_instance.api_plugin.config['core.mysql']['prefix']
    yield db
    db.close()

@pytest.fixture(scope="session")
def storage(request):
    s = {}
    yield s
