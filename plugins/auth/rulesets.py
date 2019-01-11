#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: auth.py
# Author:      Rene Fa
# Date:        11.01.2019
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

from .header import *
from . import manage_users

import datetime
import json
import copy

# ent_types: u=user, t=token, r=role
def i_apply_ruleset(ent_name, ruleset, ent_type, delete_only=False):

    # Full rebuild of all rulsets, if ent_type=2
    for username in auth_global.users_dict.items():

    # Delete old rules
    for plugin_name, action_dict in action_tree.items():
        for action_name, action in action_dict.items():
            if ent_type == 'u':
                try: action['users'].remove(ent_name)
                except: pass
            elif ent_type == 't':
                try: action['token'].remove(ent_name)
                except: pass
            elif ent_type == 'r':
                action['users'] = []
                action['token'] = []

    
