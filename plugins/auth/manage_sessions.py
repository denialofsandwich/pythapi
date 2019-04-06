#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: auth.py
# Author:      Rene Fa
# Date:        17.01.2019
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
from api_plugin import *

import time

from .header import *


def i_clean_expired_sessions():

    for session_id in list(auth_globals.session_dict.keys()):
        session = auth_globals.session_dict[session_id]
        if time.time() > session["expiration_time"]:
            e_delete_session(session_id)

    auth_globals.session_counter = 0


@api_external_function(plugin)
def e_list_sessions(username):
    return_json = []
    for session_id in auth_globals.users_dict[username]["sessions"]:
        i_entry = dict(auth_globals.session_dict[session_id])
        return_json.append(i_entry)

    return return_json


@api_external_function(plugin)
def e_create_session(reqHandler, username, options):

    if (
        auth_globals.write_through_cache_enabled
        and not username in auth_globals.users_dict
    ):
        raise WebRequestException(400, "error", "AUTH_USER_NOT_FOUND")

    if reqHandler.get_cookie("session_id"):
        if reqHandler.get_cookie("session_id") in auth_globals.session_dict:
            e_delete_session(reqHandler.get_cookie("session_id"))

    if (
        len(auth_globals.users_dict[username]["sessions"])
        >= api_config()[plugin.name]["session_create_limit"]
    ):
        raise WebRequestException(400, "error", "AUTH_SESSION_LIMIT_EXCEEDED")

    new_session_id = e_generate_random_string(cookie_length)
    expiration_time = time.time() + api_config()[plugin.name]["session_expiration_time"]

    auth_globals.session_dict[new_session_id] = {
        "username": username,
        "remote_ip": i_get_client_ip(reqHandler),
        "creation_time": time.time(),
        "expiration_time": expiration_time,
    }

    auth_globals.session_counter += 1
    if auth_globals.session_counter > session_clean_threshold:
        i_clean_expired_sessions()

    if "csrf_token" in options and options["csrf_token"] == True:
        csrf_token = e_generate_random_string(cookie_length)
        auth_globals.session_dict[new_session_id]["last_csrf_token"] = csrf_token
        reqHandler.add_header("X-CSRF-TOKEN", csrf_token)

    auth_globals.users_dict[username]["sessions"].append(new_session_id)

    kwargs = {}
    if "persistent" in options and options["persistent"] == True:
        kwargs["expires"] = expiration_time

    reqHandler.set_cookie("session_id", new_session_id, **kwargs)


@api_external_function(plugin)
def e_delete_session(session_id):

    if not session_id in auth_globals.session_dict:
        raise WebRequestException(400, "error", "AUTH_SESSION_ID_NOT_FOUND")

    username = auth_globals.session_dict[session_id]["username"]
    auth_globals.users_dict[username]["sessions"].remove(session_id)
    del auth_globals.session_dict[session_id]


@api_external_function(plugin)
def e_delete_sessions_from_user(username):

    i = 0
    while i < len(auth_globals.users_dict[username]["sessions"]):

        key = auth_globals.users_dict[username]["sessions"][i]
        del auth_globals.session_dict[key]
        del auth_globals.users_dict[username]["sessions"][i]
        continue

        i += 1


@api_action(
    plugin,
    {
        "path": "session/list",
        "method": "GET",
        "permission": "self.session.get.all",
        "f_name": {"EN": "List sessions", "DE": "Sessions auflisten"},
        "f_description": {
            "EN": "Lists all available sessions of the current user.",
            "DE": "Listet alle offenen Sessions des aktuellen Benutzers auf.",
        },
    },
)
def list_sessions(reqHandler, p, args, body):
    return {"data": e_list_sessions(auth_globals.current_user)}


@api_action(
    plugin,
    {
        "path": "session",
        "method": "POST",
        "permission": "self.session.create",
        "body": {
            "csrf_token": {
                "type": bool,
                "default": False,
                "f_name": {"EN": "CSRF-token", "DE": "CSRF-Token"},
            }
        },
        "f_name": {"EN": "Create session", "DE": "Session erstellen"},
        "f_description": {
            "EN": "Sets a cookie and creates a session.",
            "DE": "Setzt einen Cookie und öffnet eine Session.",
        },
    },
)
def create_session(reqHandler, p, args, body):
    e_create_session(reqHandler, auth_globals.current_user, body)
    return {}


@api_action(
    plugin,
    {
        "path": "session",
        "method": "DELETE",
        "permission": "self.session.delete",
        "f_name": {"EN": "Close session", "DE": "Session beenden"},
        "f_description": {
            "EN": "Quits the current session.",
            "DE": "Schließt die aktuelle Session.",
        },
    },
)
def delete_session(reqHandler, p, args, body):

    if reqHandler.get_cookie("session_id"):
        if reqHandler.get_cookie("session_id") in auth_globals.session_dict:
            e_delete_session(reqHandler.get_cookie("session_id"))
            return {}

    raise WebRequestException(400, "error", "AUTH_SESSION_NOT_FOUND")
    return {}


@api_action(
    plugin,
    {
        "path": "session/all",
        "method": "DELETE",
        "permission": "self.session.delete.all",
        "f_name": {"EN": "Close all sessions", "DE": "Alle Sessions beenden"},
        "f_description": {
            "EN": "Quits all active sessions.",
            "DE": "Schließt alle aktiven Sessions.",
        },
    },
)
def delete_all_sessions(reqHandler, p, args, body):
    e_delete_sessions_from_user(auth_globals.current_user)
    return {}
