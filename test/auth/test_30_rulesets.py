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
import json

def test_merge_permissions(pythapi):
    auth = pythapi.module_dict['auth']

    ruleset = {
        'permissions': [
            'auth.user.get.all',
            'data.read',
        ],
        'inherit': [
            'default',
        ],
    }
    default_ruleset = auth.e_get_role('auth_default')['ruleset']

    return_dict = auth.ir_merge_permissions(ruleset)

    for rule in ruleset['permissions']:
        assert rule in return_dict['permissions']

    for rule in default_ruleset['permissions']:
        assert rule in return_dict['permissions']

#def test_reduce_ruleset(pythapi):
#    auth = pythapi.module_dict['auth']
#
#    ruleset = {
#        'permissions': [
#            'auth.user.get.all',
#            'data.read',
#        ],
#        'inherit': [
#            'default',
#        ],
#    }
#    default_ruleset = auth.e_get_role('auth_default')['ruleset']
#
#    return_dict = auth.ir_merge_permissions(ruleset)
#
#    for rule in ruleset['permissions']:
#        assert rule in return_dict['permissions']
#
#    for rule in default_ruleset['permissions']:
#        assert rule in return_dict['permissions']

