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


def test_create_token(pythapi, sqldb, storage):
    username = "admin"
    token_name = "test_token"
    ruleset = {"inherit": ["default"]}

    auth = pythapi.module_dict["auth"]
    cache = auth.auth_globals

    # Execute
    token = auth.e_create_user_token(username, token_name, ruleset)
    h_token = auth.e_hash_password("", token)
    storage["h_token"] = h_token

    # Test Return Value
    assert type(token) == str

    # Test Local Cache
    assert h_token in cache.user_token_dict
    assert h_token in cache.users_dict[username]["token"]
    token_data = cache.user_token_dict[h_token]

    assert token_data["token_name"] == token_name
    assert token_data["username"] == username
    assert token_data["ruleset"] == ruleset

    # Test Database
    user_id = cache.users_dict[username]["id"]
    dbc = sqldb.cursor()

    sql = (
        """
        SELECT * FROM """
        + sqldb.prefix
        + """token WHERE user_id = %s AND token_name = %s;
    """
    )

    try:
        dbc.execute(sql, [user_id, token_name])
    except MySQLdb.IntegrityError as e:
        assert 0

    result = dbc.fetchone()

    assert result[3] == h_token
    assert json.loads(result[4]) == ruleset

    # Test permissions-index
    p_index = cache.permission_to_action_tree
    assert h_token in p_index["auth"]["user"]["get"]["self"]["_data"]["token"]
    assert (
        h_token in p_index["auth"]["user"]["edit"]["self"]["password"]["_data"]["token"]
    )

    assert h_token not in p_index["auth"]["user"]["create"]["_data"]["token"]


def test_edit_token(pythapi, sqldb, storage):
    username = "admin"
    token_name = "test_token"
    ruleset = {"permissions": ["*"], "inherit": ["default"]}

    auth = pythapi.module_dict["auth"]
    cache = auth.auth_globals
    h_token = storage["h_token"]

    # Execute
    auth.e_edit_user_token(username, token_name, ruleset)

    # Test Local Cache
    token_data = cache.user_token_dict[h_token]
    assert token_data["ruleset"] == ruleset

    # Test Database
    user_id = cache.users_dict[username]["id"]
    dbc = sqldb.cursor()

    sql = (
        """
        SELECT * FROM """
        + sqldb.prefix
        + """token WHERE user_id = %s AND token_name = %s;
    """
    )

    try:
        dbc.execute(sql, [user_id, token_name])
    except MySQLdb.IntegrityError as e:
        assert 0

    result = dbc.fetchone()

    assert json.loads(result[4]) == ruleset

    # Test permissions-index
    p_index = cache.permission_to_action_tree
    assert h_token in p_index["auth"]["user"]["get"]["self"]["_data"]["token"]
    assert (
        h_token in p_index["auth"]["user"]["edit"]["self"]["password"]["_data"]["token"]
    )
    assert h_token in p_index["auth"]["user"]["create"]["_data"]["token"]


def test_inherit_all(pythapi, sqldb, storage):
    username = "admin"
    token_name = "test_token"
    ruleset = {"inherit": ["*"]}

    auth = pythapi.module_dict["auth"]
    cache = auth.auth_globals
    h_token = storage["h_token"]

    # Execute
    auth.e_edit_user_token(username, token_name, ruleset)

    # Test permissions-index
    p_index = cache.permission_to_action_tree
    assert h_token in p_index["auth"]["user"]["get"]["self"]["_data"]["token"]
    assert (
        h_token in p_index["auth"]["user"]["edit"]["self"]["password"]["_data"]["token"]
    )
    assert h_token in p_index["auth"]["user"]["create"]["_data"]["token"]


def test_get_token(pythapi, sqldb, storage):
    username = "admin"
    token_name = "test_token"

    auth = pythapi.module_dict["auth"]
    cache = auth.auth_globals

    # Execute
    token_data = auth.e_get_user_token(username, token_name)

    in_response = ["ruleset", "token_name", "username", "time_created", "time_modified"]
    not_in_response = ["h_token"]

    for i in in_response:
        assert i in token_data

    for i in not_in_response:
        assert i not in token_data


def test_list_token(pythapi, sqldb, storage):
    username = "admin"
    token_name = "test_token"

    auth = pythapi.module_dict["auth"]
    cache = auth.auth_globals

    # Execute
    token_data_list = auth.e_list_user_token(username)

    in_response = ["ruleset", "token_name", "username", "time_created", "time_modified"]
    not_in_response = ["h_token"]

    assert len(token_data_list) != 0

    for i in in_response:
        assert i in token_data_list[0]

    for i in not_in_response:
        assert i not in token_data_list[0]


def test_delete_token(pythapi, sqldb, storage):
    username = "admin"
    token_name = "test_token"

    auth = pythapi.module_dict["auth"]
    cache = auth.auth_globals
    h_token = storage["h_token"]

    # Execute
    auth.e_delete_user_token(username, token_name)

    # Test Local Cache
    assert h_token not in cache.user_token_dict
    assert h_token not in cache.users_dict[username]["token"]

    # Test Database
    user_id = cache.users_dict[username]["id"]
    dbc = sqldb.cursor()

    sql = (
        """
        SELECT * FROM """
        + sqldb.prefix
        + """token WHERE user_id = %s AND token_name = %s;
    """
    )

    try:
        dbc.execute(sql, [user_id, token_name])
    except MySQLdb.IntegrityError as e:
        assert 0

    result = dbc.fetchone()
    assert result == None

    del storage["h_token"]
