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
import MySQLdb


@pytest.fixture(scope="module", autouse=True)
def disable_write_through_cache(pythapi):
    pythapi.module_dict["auth"].auth_globals.write_through_cache_enabled = False

    yield

    pythapi.module_dict["auth"].auth_globals.write_through_cache_enabled = True


def test_create_role(pythapi, sqldb, storage):
    role_name = "debug_role"
    ruleset = {"permissions": ["*"]}

    auth = pythapi.module_dict["auth"]

    role_id = auth.e_create_role(role_name, ruleset)

    # Checking Database
    dbc = sqldb.cursor()

    sql = (
        """
        SELECT * FROM """
        + sqldb.prefix
        + """role WHERE name = %s;
    """
    )

    try:
        dbc.execute(sql, [role_name])
    except MySQLdb.IntegrityError as e:
        assert 0

    result = dbc.fetchone()

    assert result[0] == role_id
    assert result[1] == role_name
    assert json.loads(result[2]) == ruleset


def test_edit_role(pythapi, sqldb, storage):
    role_name = "debug_role"
    ruleset = {"permissions": ["auth.role.delete"]}

    auth = pythapi.module_dict["auth"]

    auth.e_edit_role(role_name, ruleset)

    # Checking Database
    dbc = sqldb.cursor()

    sql = (
        """
        SELECT * FROM """
        + sqldb.prefix
        + """role WHERE name = %s;
    """
    )

    try:
        dbc.execute(sql, [role_name])
    except MySQLdb.IntegrityError as e:
        assert 0

    result = dbc.fetchone()

    assert json.loads(result[2]) == ruleset


def test_get_role(pythapi, sqldb, storage):
    role_name = "debug_role"

    auth = pythapi.module_dict["auth"]

    role = auth.e_get_role(role_name)

    in_response = ["ruleset", "time_created", "time_modified", "id"]

    for i in in_response:
        assert i in role


def test_list_role(pythapi, sqldb, storage):
    auth = pythapi.module_dict["auth"]

    role_list = auth.e_list_roles()

    in_response = ["ruleset", "time_created", "time_modified", "id", "role_name"]

    assert len(role_list) != 0

    for i in in_response:
        assert i in role_list[0]


def test_delete_role(pythapi, sqldb, storage):
    role_name = "debug_role"
    ruleset = {"permissions": ["auth.role.delete"]}

    auth = pythapi.module_dict["auth"]

    auth.e_delete_role(role_name)

    # Checking Database
    dbc = sqldb.cursor()

    sql = (
        """
        SELECT * FROM """
        + sqldb.prefix
        + """role WHERE name = %s;
    """
    )

    try:
        dbc.execute(sql, [role_name])
    except MySQLdb.IntegrityError as e:
        assert 0

    result = dbc.fetchone()
    assert result == None
