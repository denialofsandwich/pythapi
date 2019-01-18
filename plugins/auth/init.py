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
from . import rulesets
from . import interfaces

def i_build_permission_to_action_tree():
    for plugin_name, action_dict in action_tree.items():
        for action_name, action_data in action_dict.items():
            try:
                action_data['permission'] = plugin_name +'.' +action_data['permission']
            except:
                action_data['permission'] = plugin_name +'.' +action_name
            
            hierarchy = action_data['permission'].split('.')

            i_dict = auth_globals.permission_to_action_tree
            for i_dir in hierarchy:
                i_dict = i_dict.setdefault(i_dir, {})

            if hierarchy[-1] in i_dict:
                log.warning("Inconsistent permissions. Permission structure broken at: {}".format(action_data['permission']))
            i_dict['_data'] = action_data

@api_event(auth_globals.plugin, 'load')
def load():
    global bf_basic_auth_delay
    global bf_temporary_ban_enabled

    rulesets.e_add_subset_intersection_handler(interfaces.i_subset_permission_handler)
    rulesets.e_add_permission_reduce_handler(interfaces.i_permission_reduce_handler)

    for plugin_name in action_tree:
        for action_name in action_tree[plugin_name]:
            action_tree[plugin_name][action_name]['users'] = set()
            action_tree[plugin_name][action_name]['token'] = set()

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

    for row in manage_roles.i_list_db_roles():
        auth_globals.roles_dict[row[1]] = {
            'id': row[0],
            'ruleset': json.loads(row[2]),
            'time_created': row[3],
            'time_modified': row[4]
        }

    i_build_permission_to_action_tree()

    for username in auth_globals.users_dict:
        rulesets.i_apply_ruleset(username, 'u')

    for h_token in auth_globals.user_token_dict:
        rulesets.i_apply_ruleset(h_token, 't')

    auth_globals.bf_basic_auth_delay = api_config()[plugin.name]['bf_basic_auth_delay']
    auth_globals.bf_temporary_ban_enabled = api_config()[plugin.name]['bf_temporary_ban_enabled']

    auth_globals.write_through_cache_enabled = True
    
    return 1


