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
from . import interfaces

import datetime
import json
import copy


@api_external_function(plugin)
def e_check_custom_permissions(
    username, rule_section, target_rule, f=interfaces.i_default_permission_validator
):

    if not username in auth_globals.users_dict:
        raise WebRequestException(400, "error", "AUTH_USER_NOT_FOUND")

    if f(e_get_permissions_of_user(username), rule_section, target_rule):
        return 1

    return 0


@api_external_function(plugin)
def e_check_custom_permissions_of_current_user(
    rule_section, target_rule, f=interfaces.i_default_permission_validator
):

    if auth_globals.auth_type == "token":
        return f(
            e_get_permissions_of_token(auth_globals.current_token),
            rule_section,
            target_rule,
        )
    else:
        return f(
            e_get_permissions_of_user(auth_globals.current_user, reduced=False),
            rule_section,
            target_rule,
        )

    return 0


# To merge dicts and lists
def update_2(d, u):
    for k, v in u.items():
        if isinstance(v, collections.Mapping):
            d[k] = update(d.get(k, {}), v)
        elif type(v) == list and k in d:
            d[k].extend(v)
        else:
            d[k] = v

    return d


def ir_merge_permissions(ruleset, depth=-1):
    if depth > len(auth_globals.roles_dict) + 1:
        raise WebRequestException(400, "error", "GENERAL_RECURSIVE_LOOP")

    parent_list = ruleset.get("inherit", [])

    return_json = copy.deepcopy(ruleset)
    try:
        del return_json["inherit"]
    except:
        pass

    for parent in parent_list:
        try:
            update_2(
                return_json,
                ir_merge_permissions(
                    auth_globals.roles_dict[parent]["ruleset"], depth + 1
                ),
            )
        except KeyError as e:
            log.warning("Inconsistent ruleset: Unknown role {}.".format(parent))

    return return_json


@api_external_function(plugin)
def e_add_permission_reduce_handler(f):
    auth_globals.permission_reduce_handlers.append(f)


def i_reduce_ruleset(ruleset):
    ruleset = copy.deepcopy(ruleset)

    for handler in auth_globals.permission_reduce_handlers:
        ruleset = handler(ruleset)

    return ruleset


@api_external_function(plugin)
def e_get_permissions_of_user(username, reduced=True):
    if not username in auth_globals.users_dict:
        raise WebRequestException(400, "error", "AUTH_USER_NOT_FOUND")

    return_json = ir_merge_permissions(auth_globals.users_dict[username]["ruleset"])

    if reduced:
        return_json = i_reduce_ruleset(return_json)

    return return_json


@api_external_function(plugin)
def e_get_permissions_of_token(h_token, reduced=True):
    if not h_token in auth_globals.user_token_dict:
        raise WebRequestException(400, "error", "AUTH_TOKEN_NOT_FOUND")

    token_data = auth_globals.user_token_dict[h_token]
    ruleset = token_data["ruleset"]

    if "inherit" in token_data["ruleset"] and "*" in token_data["ruleset"]["inherit"]:
        ruleset = auth_globals.users_dict[token_data["username"]]["ruleset"]

    return_json = ir_merge_permissions(ruleset)

    if reduced:
        return_json = i_reduce_ruleset(return_json)

    return return_json


@api_external_function(plugin)
def e_get_permissions():
    if auth_type == "token":
        return e_get_permissions_of_token(auth_globals.current_token)
    else:
        return e_get_permissions_of_user(e_get_current_user())


@api_external_function(plugin)
def e_add_subset_intersection_handler(f):
    auth_globals.subset_intersection_handlers.append(f)


@api_external_function(plugin)
def e_intersect_subset(ruleset, subset):
    return_subset = {}

    for handler in auth_globals.subset_intersection_handlers:
        return_subset.update(handler(ruleset, subset))

    return return_subset


def evaluate_and_update_token(username, h_token):
    user_ruleset = e_get_permissions_of_user(username)
    user_ruleset["inherit"] = auth_globals.users_dict[username]["ruleset"].get(
        "inherit", []
    )

    ruleset = auth_globals.user_token_dict[h_token]["ruleset"]

    still_valid = True

    if "inherit" in ruleset and "*" in ruleset["inherit"]:
        return

    intersected = e_intersect_subset(user_ruleset, ruleset)

    if ruleset.get("inherit", []) != intersected.get(
        "inherit", []
    ) and "*" in user_ruleset.get("permissions", []):
        pass
    elif intersected != ruleset:
        still_valid = False

    if not still_valid:
        token_name = auth_globals.user_token_dict[h_token]["token_name"]
        plugin.e_edit_user_token(
            username, token_name, intersected
        )  # Workaround to supress import-loop


def evaluate_token_of_user(username):
    for username, user_data in auth_globals.users_dict.items():
        for h_token in user_data["token"]:
            evaluate_and_update_token(username, h_token)


def evalueate_token_of_all_users():
    for username in auth_globals.users_dict:
        evaluate_token_of_user(username)


def ir_add_entity_to_access_list(d, ent_name, ent_type, depth=0):
    if depth > 64:
        raise WebRequestException(400, "error", "GENERAL_RECURSIVE_LOOP")

    # Traverses the dict
    for k, v in d.items():
        if k == "_data":
            i_add_entity_to_access_list(d["_data"], ent_name, ent_type)
        else:
            ir_add_entity_to_access_list(d[k], ent_name, ent_type)


def i_add_entity_to_access_list(d, ent_name, ent_type):
    if ent_type == "u":
        d["users"].add(ent_name)
    elif ent_type == "t":
        d["token"].add(ent_name)


# ent_types: u=user, t=token, r=role
def i_apply_ruleset(ent_name, ent_type, delete_only=False):

    # Full rebuild of all rulsets, if ent_type='r'
    if ent_type == "r":
        for username in auth_globals.users_dict:
            i_apply_ruleset(username, "u", delete_only)

        for h_token in auth_globals.user_token_dict:
            i_apply_ruleset(h_token, "t", delete_only)

        return

    # Delete old rules
    for plugin_name, action_dict in action_tree.items():
        for action_name, action in action_dict.items():
            if ent_type == "u":
                try:
                    action["users"].remove(ent_name)
                except:
                    pass
            elif ent_type == "t":
                try:
                    action["token"].remove(ent_name)
                except:
                    pass

    if delete_only:
        return

    if ent_type == "u":
        ruleset = e_get_permissions_of_user(ent_name)
    elif ent_type == "t":
        ruleset = e_get_permissions_of_token(ent_name)

    else:
        log.error("Unknown ent_type: {}".format(ent_type))
        return

    for permission in ruleset.get("permissions", []):
        # Get action and set user as permitted entity
        try:
            wildcard = False
            hierarchy = permission.split(".")

            i_dict = auth_globals.permission_to_action_tree
            for i_dir in hierarchy:
                if i_dir == "*":
                    wildcard = True
                    break
                else:
                    i_dict = i_dict[i_dir]

            if hierarchy[-1] in i_dict:
                log.warning(
                    "Inconsistent permissions. Permission structure broken at: {}".format(
                        action_data["permission"]
                    )
                )

            if wildcard:
                ir_add_entity_to_access_list(i_dict, ent_name, ent_type)
            else:
                i_add_entity_to_access_list(i_dict["_data"], ent_name, ent_type)
        except KeyError as e:
            log.warning("Permission {} does not exist.".format(permission))


@api_external_function(plugin)
def e_get_permissions():
    if auth_globals.auth_type == "token":
        return e_get_permissions_of_token(auth_globals.current_token)
    else:
        return e_get_permissions_of_user(auth_globals.current_user)


@api_action(
    plugin,
    {
        "path": "permissions",
        "method": "GET",
        "permission": "self.get.permissions",
        "f_name": {"EN": "Get permissions", "DE": "Zeige Berechtigungen"},
        "f_description": {
            "EN": "Returns a merged list of all permissions.",
            "DE": "Gibt eine zusammengesetzte Liste mit allen Berechtigungen zurück.",
        },
    },
)
def get_permissions(reqHandler, p, args, body):
    return {"data": e_get_permissions()}
