#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: auth.py
# Author:      Rene Fa
# Date:        10.01.2019
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

sys.path.append("..")
import MySQLdb
from api_plugin import *

from .header import *
from . import rulesets
from . import manage_users

import copy
import datetime


def i_get_db_user_token(username, token_name):
    db_prefix = api_config()["core.mysql"]["prefix"]
    db = api_mysql_connect()
    dbc = db.cursor()

    if auth_globals.write_through_cache_enabled:
        if not username in auth_globals.users_dict:
            raise WebRequestException(400, "error", "AUTH_USER_NOT_FOUND")

        user_id = auth_globals.users_dict[username]["id"]

    else:
        user_id = manage_users.i_get_db_user(username)[0]

    sql = (
        """
        SELECT * FROM """
        + db_prefix
        + """token WHERE user_id = %s AND token_name = %s;
    """
    )

    try:
        dbc.execute(sql, [user_id, token_name])

    except MySQLdb.IntegrityError as e:
        api_log().error("i_get_db_user_token: {}".format(api_tr("GENERAL_SQL_ERROR")))
        raise WebRequestException(501, "error", "GENERAL_SQL_ERROR")

    result = dbc.fetchone()
    if result == None:
        raise WebRequestException(400, "error", "AUTH_TOKEN_NOT_FOUND")

    return result


def i_list_db_user_token(username):
    db_prefix = api_config()["core.mysql"]["prefix"]
    db = api_mysql_connect()
    dbc = db.cursor()

    sql = (
        """
        SELECT """
        + db_prefix
        + """token.id, name, token_name, h_token, """
        + db_prefix
        + """token.ruleset, """
        + db_prefix
        + """token.time_created, """
        + db_prefix
        + """token.time_modified
            FROM """
        + db_prefix
        + """token
            JOIN """
        + db_prefix
        + """user
            ON user_id = """
        + db_prefix
        + """user.id
            WHERE name = %s;
    """
    )

    try:
        dbc.execute(sql, [username])

    except MySQLdb.IntegrityError as e:
        api_log().error("i_list_db_user_token: {}".format(api_tr("GENERAL_SQL_ERROR")))
        raise WebRequestException(501, "error", "GENERAL_SQL_ERROR")

    return dbc.fetchall()


def i_list_db_token():
    db_prefix = api_config()["core.mysql"]["prefix"]
    db = api_mysql_connect()
    dbc = db.cursor()

    sql = (
        """
        SELECT """
        + db_prefix
        + """token.id, name, token_name, h_token, """
        + db_prefix
        + """token.ruleset, """
        + db_prefix
        + """token.time_created, """
        + db_prefix
        + """token.time_modified
            FROM """
        + db_prefix
        + """token
            JOIN """
        + db_prefix
        + """user
            ON user_id = """
        + db_prefix
        + """user.id;
    """
    )

    try:
        dbc.execute(sql)

    except MySQLdb.IntegrityError as e:
        api_log().error("i_list_db_token: {}".format(api_tr("GENERAL_SQL_ERROR")))
        raise WebRequestException(501, "error", "GENERAL_SQL_ERROR")

    return dbc.fetchall()


def i_get_local_user_token(username, token_name):
    for key in auth_globals.users_dict[username]["token"]:
        if not "token_name" in auth_globals.user_token_dict[key]:
            continue

        if auth_globals.user_token_dict[key]["token_name"] == token_name:
            i_entry = copy.deepcopy(auth_globals.user_token_dict[key])
            return i_entry

    raise WebRequestException(400, "error", "AUTH_TOKEN_NOT_FOUND")


def i_list_local_user_token(username):
    return_json = []
    for key in auth_globals.users_dict[username]["token"]:
        i_entry = copy.deepcopy(auth_globals.user_token_dict[key])
        return_json.append(i_entry)

    return return_json


@api_external_function(plugin)
def e_get_user_token(username, token_name):
    if auth_globals.write_through_cache_enabled:
        return i_get_local_user_token(username, token_name)

    else:
        token = i_get_db_user_token(username, token_name)

        return_json = {
            "token_name": token_name,
            "username": username,
            "ruleset": json.loads(token[4]),
            "time_created": token[5],
            "time_modified": token[6],
        }

        return return_json


@api_external_function(plugin)
def e_list_user_token(username):
    if auth_globals.write_through_cache_enabled:
        return i_list_local_user_token(username)

    else:
        return_json = []
        for token in i_list_db_user_token(username):
            i_entry = {
                "token_name": token[2],
                "username": token[1],
                "ruleset": json.loads(token[4]),
                "time_created": token[5],
                "time_modified": token[6],
            }

            return_json.append(i_entry)

        return return_json


def i_verify_and_reduce_token_ruleset(username, ruleset):
    user_ruleset = rulesets.e_get_permissions_of_user(username)
    user_ruleset["inherit"] = manage_users.e_get_user(username)["ruleset"].get(
        "inherit", []
    )

    inherit_all = False
    if "inherit" in ruleset and "*" in ruleset["inherit"]:
        inherit_all = True
        ruleset["inherit"].remove("*")

    intersected = rulesets.e_intersect_subset(user_ruleset, ruleset)

    if ruleset.get("inherit", []) != intersected.get(
        "inherit", []
    ) and "*" in user_ruleset.get("permissions", []):
        pass
    elif intersected != ruleset:
        raise WebRequestException(401, "unauthorized", "AUTH_PERMISSIONS_DENIED")

    if inherit_all:
        ruleset = {"inherit": ["*"]}
    else:
        ruleset = rulesets.i_reduce_ruleset(ruleset)

    return ruleset


@api_external_function(plugin)
def e_create_user_token(username, token_name, ruleset={"inherit": ["*"]}):
    if token_name == "list":
        raise WebRequestException(400, "error", "AUTH_EXECUTION_DENIED")

    db_prefix = api_config()["core.mysql"]["prefix"]
    db = api_mysql_connect()
    dbc = db.cursor()

    if auth_globals.write_through_cache_enabled:
        if not username in auth_globals.users_dict:
            raise WebRequestException(400, "error", "AUTH_USER_NOT_FOUND")

        user_id = auth_globals.users_dict[username]["id"]

    else:
        user_id = manage_users.i_get_db_user(username)[0]

    ruleset = i_verify_and_reduce_token_ruleset(username, ruleset)

    new_token = e_generate_random_string(cookie_length)
    h_new_token = e_hash_password("", new_token)

    sql = (
        """
        INSERT INTO """
        + db_prefix
        + """token (
                token_name, h_token, user_id, ruleset
            )
            VALUES (%s, %s, %s, %s);
    """
    )

    try:
        dbc.execute(sql, [token_name, h_new_token, user_id, json.dumps(ruleset)])
        db.commit()

    except MySQLdb.IntegrityError as e:
        raise WebRequestException(400, "error", "AUTH_TOKEN_EXISTS")

    if auth_globals.write_through_cache_enabled:
        auth_globals.user_token_dict[h_new_token] = {
            "username": username,
            "token_name": token_name,
            "ruleset": ruleset,
            "time_created": datetime.datetime.now(),
            "time_modified": datetime.datetime.now(),
        }
        auth_globals.users_dict[username]["token"].append(h_new_token)

        rulesets.i_apply_ruleset(h_new_token, "t")

    return new_token


@api_external_function(plugin)
def e_edit_user_token(username, token_name, ruleset):

    if token_name == "list":
        raise WebRequestException(400, "error", "AUTH_EXECUTION_DENIED")

    db_prefix = api_config()["core.mysql"]["prefix"]
    db = api_mysql_connect()
    dbc = db.cursor()

    if auth_globals.write_through_cache_enabled:
        if not username in auth_globals.users_dict:
            raise WebRequestException(400, "error", "AUTH_USER_NOT_FOUND")

        user_id = auth_globals.users_dict[username]["id"]

    else:
        user_id = manage_users.i_get_db_user(username)[0]

    ruleset = i_verify_and_reduce_token_ruleset(username, ruleset)

    # Check if the token exists
    i_get_db_user_token(username, token_name)

    sql = (
        """
        UPDATE """
        + db_prefix
        + """token
            SET ruleset = %s
            WHERE user_id = %s AND token_name = %s;
    """
    )

    try:
        dbc.execute(sql, [json.dumps(ruleset), user_id, token_name])
        db.commit()

    except MySQLdb.IntegrityError as e:
        api_log().error("e_delete_user_token: {}".format(api_tr("GENERAL_SQL_ERROR")))
        raise WebRequestException(501, "error", "GENERAL_SQL_ERROR")

    if auth_globals.write_through_cache_enabled:
        for i, h_token in enumerate(auth_globals.users_dict[username]["token"]):
            if auth_globals.user_token_dict[h_token]["token_name"] == token_name:
                auth_globals.user_token_dict[h_token]["ruleset"] = ruleset
                auth_globals.user_token_dict[h_token][
                    "time_modified"
                ] = datetime.datetime.now()
                rulesets.i_apply_ruleset(h_token, "t")
                break


@api_external_function(plugin)
def e_delete_user_token(username, token_name):

    if token_name == "list":
        raise WebRequestException(400, "error", "AUTH_EXECUTION_DENIED")

    db_prefix = api_config()["core.mysql"]["prefix"]
    db = api_mysql_connect()
    dbc = db.cursor()

    if auth_globals.write_through_cache_enabled:
        if not username in auth_globals.users_dict:
            raise WebRequestException(400, "error", "AUTH_USER_NOT_FOUND")

        user_id = auth_globals.users_dict[username]["id"]

    else:
        user_id = manage_users.i_get_db_user(username)[0]

    # Check if the token exists
    i_get_db_user_token(username, token_name)

    sql = (
        """
        DELETE FROM """
        + db_prefix
        + """token 
            WHERE user_id = %s AND token_name = %s;
    """
    )

    try:
        dbc.execute(sql, [user_id, token_name])
        db.commit()

    except MySQLdb.IntegrityError as e:
        api_log().error("e_delete_user_token: {}".format(api_tr("GENERAL_SQL_ERROR")))
        raise WebRequestException(501, "error", "GENERAL_SQL_ERROR")

    if auth_globals.write_through_cache_enabled:
        for i in range(len(auth_globals.users_dict[username]["token"])):
            key = auth_globals.users_dict[username]["token"][i]
            if auth_globals.user_token_dict[key]["token_name"] == token_name:
                h_token = key

                rulesets.i_apply_ruleset(h_token, "t", delete_only=True)

                del auth_globals.user_token_dict[h_token]
                del auth_globals.users_dict[username]["token"][i]
                break


@api_action(
    plugin,
    {
        "path": "token/list",
        "method": "GET",
        "permission": "self.token.get.all",
        "args": {
            "verbose": {
                "type": bool,
                "default": False,
                "f_name": {"EN": "Verbose", "DE": "Ausführlich"},
            }
        },
        "f_name": {"EN": "List API token", "DE": "API Token auflisten"},
        "f_description": {
            "EN": "Lists all available API token.",
            "DE": "Listet alle erstellten API Token auf.",
        },
    },
)
def list_user_tokens(reqHandler, p, args, body):
    full_token_list = e_list_user_token(auth_globals.current_user)

    if args["verbose"]:
        return {"data": full_token_list}

    else:
        token_name_list = []
        for token in full_token_list:
            token_name_list.append(token["token_name"])

        return {"data": token_name_list}


@api_action(
    plugin,
    {
        "path": "token/*",
        "method": "GET",
        "permission": "self.token.get",
        "params": [
            {
                "name": "token_name",
                "type": str,
                "regex": r"^[a-zA-Z0-9_-]{1,31}$",
                "f_name": {"EN": "Token name", "DE": "Tokenname"},
            }
        ],
        "f_name": {"EN": "Get API token", "DE": "Zeige API Token"},
        "f_description": {
            "EN": "Returns a single API token.",
            "DE": "Gibt ein einzelnes API Token zurück.",
        },
    },
)
def get_user_token(reqHandler, p, args, body):
    return {"data": e_get_user_token(auth_globals.current_user, p[0])}


@api_action(
    plugin,
    {
        "path": "token/*",
        "method": "POST",
        "permission": "self.token.create",
        "params": [
            {
                "name": "token_name",
                "type": str,
                "regex": r"^[a-zA-Z0-9_-]{1,31}$",
                "f_name": {"EN": "Token name", "DE": "Tokenname"},
            }
        ],
        "f_name": {"EN": "Create API token", "DE": "API Token erstellen"},
        "f_description": {
            "EN": "Creates a new API token.",
            "DE": "Erstellt ein neues API Token.",
        },
    },
)
def create_user_token(reqHandler, p, args, body):
    return {"token": e_create_user_token(auth_globals.current_user, p[0], body)}


@api_action(
    plugin,
    {
        "path": "token/*",
        "method": "PUT",
        "permission": "self.token.edit",
        "params": [
            {
                "name": "token_name",
                "type": str,
                "regex": r"^[a-zA-Z0-9_-]{1,31}$",
                "f_name": {"EN": "Token name", "DE": "Tokenname"},
            }
        ],
        "f_name": {"EN": "Edit API token", "DE": "API Token editieren"},
        "f_description": {
            "EN": "Edit's an API token.",
            "DE": "Editiert ein API Token.",
        },
    },
)
def edit_user_token(reqHandler, p, args, body):
    e_edit_user_token(auth_globals.current_user, p[0], body)
    return {}


@api_action(
    plugin,
    {
        "path": "token/*",
        "method": "DELETE",
        "permission": "self.token.delete",
        "params": [
            {
                "name": "token_name",
                "type": str,
                "regex": r"^[a-zA-Z0-9_-]{1,31}$",
                "f_name": {"EN": "Token name", "DE": "Tokenname"},
            }
        ],
        "f_name": {"EN": "Delete API token", "DE": "API Token löschen"},
        "f_description": {"EN": "Deletes an API token.", "DE": "Löscht ein API Token."},
    },
)
def delete_user_token(reqHandler, p, args, body):
    e_delete_user_token(auth_globals.current_user, p[0])
    return {}
