#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: auth
# Author:      Rene Fa
# Date:        08.01.2019
# Version:     1.6
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

import sys
from api_plugin import *
import MySQLdb
import json

from .header import *
from . import manage_users
from . import manage_roles
from . import manage_token

@api_event(auth_globals.plugin, 'load')
def load():
    global bf_basic_auth_delay
    global bf_temporary_ban_enabled

#    e_add_subset_intersection_handler(i_subset_permission_handler)
#    e_add_permission_reduce_handler(i_permission_reduce_handler)

    for plugin_name in action_tree:
        for action_name in action_tree[plugin_name]:
            action_tree[plugin_name][action_name]['users'] = []
            action_tree[plugin_name][action_name]['token'] = []

    for row in manage_users.i_list_db_user():
        auth_globals.users_dict[row[1]] = {
            'id': row[0],
            'type': row[2],
            'h_password': row[3],
            'token': [],
            'sessions': [],
            'ruleset': json.loads(row[4]),
            'time_created': row[5],
            'time_modified': row[6]
        }

    for row in manage_token.i_list_db_token():
        auth_globals.user_token_dict[row[3]] = {
            'username': row[1],
            'token_name': row[2],
            'ruleset': json.loads(row[4]),
            'time_created': row[5],
            'time_modified': row[6]
        }
        auth_globals.users_dict[row[1]]['token'].append(row[3])
#
    for row in manage_roles.i_list_db_roles():
        auth_globals.roles_dict[row[1]] = {
            'id': row[0],
            'ruleset': json.loads(row[2]),
            'time_created': row[3],
            'time_modified': row[4]
        }

    for username, user_data in auth_globals.users_dict.items():
        i_apply_ruleset(username, user_data['ruleset'], 0)

    for h_token, token_data in auth_globals.user_token_dict.items():
        i_apply_ruleset(h_token, token_data['ruleset'], 1)

    bf_basic_auth_delay = api_config()[plugin.name]['bf_basic_auth_delay']
    bf_temporary_ban_enabled = api_config()[plugin.name]['bf_temporary_ban_enabled']

    auth_globals.write_through_cache_enabled = True

    
    return 1


