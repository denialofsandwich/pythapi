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

# TODO: Test config parser
# TODO: Test arg parser
# TODO: Test Empty Request
    # : Test Parameter fail validation

import pytest
import importlib

import argparse
import test.tools.pythapi_testing_tools as ptt

@pytest.fixture(scope="module")
def pythapi(request):
    pythapi_instance = ptt.start_pythapi(
        debug_override_config="test/core/configs/base_conf.ini"
    )

    yield pythapi_instance

    with pytest.raises(SystemExit) as pytest_wrapped_e:
        pythapi_instance.terminate_application()

def test_basic_request(pythapi):
    assert 1 == 1