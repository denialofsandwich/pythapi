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

#def test_create_role(pythapi, sqldb, storage):
#    role_name = 'debug_role'
#    ruleset = {
#        'permissions': [
#            '*'
#        ]
#    }
#
#    auth = pythapi.module_dict['auth']
#    cache = auth.auth_globals
#
#    role_id = auth.e_create_role(role_name, ruleset)
#
#    # Checking local cache
#    assert role_name in cache.roles_dict
#    role = cache.roles_dict[role_name]
#    assert role['id'] == role_id
#    assert role['ruleset'] == ruleset
#
#    # Checking Database
#    dbc = sqldb.cursor()
#
#    sql = """
#        SELECT * FROM """ +sqldb.prefix +"""role WHERE name = %s;
#    """
#    
#    try:
#        dbc.execute(sql, [role_name])
#    except MySQLdb.IntegrityError as e:
#        assert 0
#
#    result = dbc.fetchone()
#
#    assert result[0] ==  role_id
#    assert result[1] == role_name
#    assert json.loads(result[2]) == ruleset
#
