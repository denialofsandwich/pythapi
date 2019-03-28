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

def test_create_user(pythapi, sqldb, storage):
    username = 'peter'
    ruleset = {
        'inherit': [
            'default'
        ]
    }

    auth = pythapi.module_dict['auth']
    cache = auth.auth_globals

    # Execute
    user_id = auth.e_create_user(username, 'default', {
        'password': '1234',
        'ruleset': ruleset,
    })

    # Test Return Value
    assert type(user_id) == int

    # Test Local Cache
    assert username in cache.users_dict
    user = cache.users_dict[username]
    assert user['id'] == user_id

    # Test Database
    dbc = sqldb.cursor()

    sql = """
        SELECT * FROM """ +sqldb.prefix +"""user WHERE id = %s;
    """

    try:
        dbc.execute(sql, [user_id])
    except MySQLdb.IntegrityError as e:
        assert 0

    result = dbc.fetchone()

    assert result[0] ==  user_id
    assert result[1] == username
    storage['uc_pwhash'] = result[2]
    assert json.loads(result[4]) == ruleset

    # Test permissions-index
    p_index = cache.permission_to_action_tree
    assert username in p_index['auth']['user']['get']['self']['_data']['users']
    assert username in p_index['auth']['user']['edit']['self']['password']['_data']['users']

    assert username not in p_index['auth']['user']['create']['_data']['users']

def test_edit_user(pythapi, sqldb, storage):
    username = 'peter'
    ruleset = {
        'permissions': [
            'auth.user.create',
        ],
        'inherit': [
            'default'
        ]
    }

    auth = pythapi.module_dict['auth']
    cache = auth.auth_globals

    # Execute
    auth.e_edit_user(username, {
        'password': '12346',
        'ruleset': ruleset,
    })

    # Test Local Cache
    assert username in cache.users_dict
    assert cache.users_dict[username]['ruleset'] == ruleset

    # Test Database
    dbc = sqldb.cursor()
    user_id = cache.users_dict[username]['id']

    sql = """
        SELECT * FROM """ +sqldb.prefix +"""user WHERE id = %s;
    """

    try:
        dbc.execute(sql, [user_id])
    except MySQLdb.IntegrityError as e:
        assert 0

    result = dbc.fetchone()

    assert result[1] == username
    assert storage['uc_pwhash'] != result[3]
    assert json.loads(result[4]) == ruleset

    # Test permissions-index
    p_index = cache.permission_to_action_tree
    assert username in p_index['auth']['user']['get']['self']['_data']['users']
    assert username in p_index['auth']['user']['edit']['self']['password']['_data']['users']
    assert username in p_index['auth']['user']['create']['_data']['users']

def test_get_user(pythapi, storage):
    username = 'peter'

    auth = pythapi.module_dict['auth']

    user = auth.e_get_user(username)

    in_response = ['ruleset', 'username', 'time_created', 'time_modified', 'type', 'id']
    not_in_response = ['h_password']

    for i in in_response:
        assert i in user

    for i in not_in_response:
        assert i not in user

    assert user['username'] == username

def test_list_user(pythapi, storage):
    auth = pythapi.module_dict['auth']

    user_list = auth.e_list_users()

    in_response = ['ruleset', 'username', 'time_created', 'time_modified', 'type', 'id']
    not_in_response = ['h_password']

    assert len(user_list) != 0

    for i in in_response:
        assert i in user_list[0]

    for i in not_in_response:
        assert i not in user_list[0]

def test_delete_user(pythapi, sqldb, storage):
    username = 'peter'

    auth = pythapi.module_dict['auth']
    cache = auth.auth_globals
    user_id = cache.users_dict[username]['id']

    auth.e_delete_user(username)

    assert username not in cache.users_dict

    dbc = sqldb.cursor()

    sql = """
        SELECT * FROM """ +sqldb.prefix +"""user WHERE id = %s;
    """

    try:
        dbc.execute(sql, [user_id])
    except MySQLdb.IntegrityError as e:
        assert 0

    result = dbc.fetchone()
    assert result == None

    # Test permissions-index
    p_index = cache.permission_to_action_tree
    assert username not in p_index['auth']['user']['get']['self']['_data']['users']
    assert username not in p_index['auth']['user']['edit']['self']['password']['_data']['users']

    assert username not in p_index['auth']['user']['create']['_data']['users']

    del storage['uc_pwhash']
