#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: time-plugin.py
# Author:      Rene Fa
# Date:        06.07.2018
# Version:     0.4
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
import time
import datetime
from threading import Timer
import http.client
from base64 import b64encode
import json

plugin = api_plugin()
plugin.name = "time"
plugin.version = "0.4"
plugin.essential = False
plugin.info["f_name"] = {"EN": "Time control", "DE": "Zeitsteuerung"}

plugin.info["f_description"] = {
    "EN": "This plugin controls time-based events.",
    "DE": "Dieses Plugin steuert zeitgestuerte Events.",
}

plugin.info["f_icon"] = {"EN": "timer"}

plugin.depends = [
    {"name": "auth", "required": True},
    {"name": "data", "required": True},
]

plugin.config_defaults = {}

plugin.translation_dict = {
    "TIME_EVENT_NOT_FOUND": {"EN": "Event not found.", "DE": "Event nicht gefunden."},
    "TIME_EVENT_EXISTS": {
        "EN": "Event already exist.",
        "DE": "Event existiert bereits.",
    },
    "TIME_STATE_ALREADY_SET": {
        "EN": "Event is already in target state.",
        "DE": "Event ist bereits in Zielzustand.",
    },
}


class TimedIntervalEvent:
    def __init__(
        self, name, func, func_args=[], func_kwargs={}, repeat=0, enabled=1, interval=60
    ):

        self.name = name
        self.func = func
        self.repeat = repeat
        self.enabled = 0
        self.interval = interval
        self.func_args = func_args
        self.func_kwargs = func_kwargs

        self.setEnabled(enabled)

    def calc_time(self):
        return self.interval

    def t_scheduler(self):
        # Restart interval
        if self.repeat:
            self.timer = Timer(self.calc_time(), self.t_scheduler, ())
            self.timer.start()

        else:
            del event_dict[self.name]
            self.enabled = 0

        if log.loglevel >= 5:
            log.access("t_event {}".format(self.name))
        self.func(*self.func_args, **self.func_kwargs)

    def setEnabled(self, state):
        if state and not self.enabled:

            self.timer = Timer(self.calc_time(), self.t_scheduler, ())
            self.timer.start()
            self.enabled = 1

        elif not state and self.enabled:
            self.timer.cancel()
            self.enabled = 0


class TimedStaticEvent(TimedIntervalEvent):
    def __init__(
        self,
        name,
        func,
        func_args=[],
        func_kwargs={},
        repeat=0,
        enabled=1,
        minute=[-1],
        hour=[-1],
        day_of_week=[-1],
        day_of_month=[-1],
        month=[-1],
        year=[-1],
    ):

        super().__init__(name, func, func_args, func_kwargs, repeat, 0)

        self.minute = minute
        self.hour = hour
        self.day_of_week = day_of_week
        self.day_of_month = day_of_month
        self.month = month
        self.year = year

        self.setEnabled(enabled)

    def i_recall_timer(self):
        self.timer = Timer(self.calc_time(), self.t_scheduler, ())
        self.timer.start()

    def i_check_time_unit(self, value_list, reference):
        if value_list[0] != -1:
            for value in value_list:
                if value == reference:
                    return 1
            return 0
        return 1

    def t_scheduler(self):
        time = datetime.datetime.now()

        if (
            not self.i_check_time_unit(self.minute, time.minute)
            or not self.i_check_time_unit(self.hour, time.hour)
            or not self.i_check_time_unit(self.day_of_week, time.weekday() + 1)
            or not self.i_check_time_unit(self.day_of_month, time.day)
            or not self.i_check_time_unit(self.month, time.month)
            or not self.i_check_time_unit(self.year, time.year)
        ):

            self.i_recall_timer()
            return

        super().t_scheduler()

    def calc_time(self):
        wild_set = 0

        target_date = datetime.datetime.now()

        target_date = target_date.replace(microsecond=10)
        target_date = target_date.replace(second=0)
        target_date = target_date + datetime.timedelta(minutes=1)

        return (target_date - datetime.datetime.now()).total_seconds()


@api_external_function(plugin)
def e_get_timed_event(event_name):
    if not event_name in event_dict:
        raise WebRequestException(400, "error", "TIME_EVENT_NOT_FOUND")

    event = event_dict[event_name]

    return_json = {}
    return_json["name"] = event_name
    return_json["repeat"] = event.repeat
    return_json["enabled"] = event.enabled
    return_json["type"] = "unknown"
    return_json["func_name"] = event.func.__name__

    return_json["func_args"] = event.func_args
    return_json["func_kwargs"] = event.func_kwargs

    if type(event) == TimedIntervalEvent:
        return_json["type"] = "interval"

        return_json["interval"] = event.interval

    elif type(event) == TimedStaticEvent:
        return_json["type"] = "static"

        return_json["minute"] = event.minute
        return_json["hour"] = event.hour
        return_json["day_of_week"] = event.day_of_week
        return_json["day_of_month"] = event.day_of_month
        return_json["month"] = event.month
        return_json["year"] = event.year

    return return_json


@api_external_function(plugin)
def e_list_timed_events():
    return_json = []
    for event_name in event_dict:
        return_json.append(e_get_timed_event(event_name))

    return return_json


@api_external_function(plugin)
def e_register_timed_interval_event(
    event_name,
    func,
    func_args=[],
    func_kwargs={},
    repeat=0,
    enabled=1,
    interval=60,
    **kwargs,
):

    if event_name in event_dict:
        raise WebRequestException(400, "error", "TIME_EVENT_EXISTS")

    event_dict[event_name] = TimedIntervalEvent(
        event_name, func, func_args, func_kwargs, repeat, enabled, interval
    )


@api_external_function(plugin)
def e_register_timed_static_event(
    event_name,
    func,
    func_args=[],
    func_kwargs={},
    repeat=0,
    enabled=1,
    minute=[-1],
    hour=[-1],
    day_of_week=[-1],
    day_of_month=[-1],
    month=[-1],
    year=[-1],
    **kwargs,
):

    if event_name in event_dict:
        raise WebRequestException(400, "error", "TIME_EVENT_EXISTS")

    event_dict[event_name] = TimedStaticEvent(
        event_name,
        func,
        func_args,
        func_kwargs,
        repeat,
        enabled,
        minute,
        hour,
        day_of_week,
        day_of_month,
        month,
        year,
    )


@api_external_function(plugin)
def e_set_event_state(event_name, state):
    if not event_name in event_dict:
        raise WebRequestException(400, "error", "TIME_EVENT_NOT_FOUND")

    event_dict[event_name].setEnabled(state)


def test_func(text):
    log.debug("Text: {}".format(text))


@api_external_function(plugin)
def etv_action_request_template(current_user, method, path, body={}):

    auth = api_plugins()["auth"]
    data = api_plugins()["data"]

    try:
        auth.e_get_user_token(current_user, "_timer_key")
        token = data.e_read_data("/user/" + current_user + "/timer/user_token")

    except WebRequestException:
        token = auth.e_create_user_token(current_user, "_timer_key")
        data.e_write_data("/user/" + current_user + "/timer/user_token", token)

    port = api_config()["core.web"]["http_port"][0]

    c = http.client.HTTPConnection("127.0.0.1", port)

    headers = {"Authorization": "Bearer %s" % token}

    c.request(method, path, json.dumps(body), headers=headers)
    res = c.getresponse()
    data = res.read()

    log.debug("{} {}".format(api_environment_variables()["transaction_id"], data))


# @api_event(plugin, 'install')
# def install():
#    return 1
#
# @api_event(plugin, 'uninstall')
# def uninstall():
#    return 1
#
@api_event(plugin, "load")
def load():
    global event_dict
    event_dict = {}

    return 1


@api_event(plugin, "terminate")
def terminate():

    log.debug("Terminating all scheduled timed events...")
    for event_name in event_dict:
        event = event_dict[event_name]
        event.setEnabled(0)

    for event_name in dict(event_dict):
        event_dict[event_name].timer.join()

    return 1


@api_action(
    plugin,
    {
        "path": "event/list",
        "method": "GET",
        "args": {
            "verbose": {
                "type": bool,
                "default": False,
                "f_name": {"EN": "Verbose", "DE": "Ausführlich"},
            }
        },
        "f_name": {"EN": "List events", "DE": "Events auflisten"},
        "f_description": {
            "EN": "Returns a list with all timed events.",
            "DE": "Gibt eine Liste mit allen zeitgesteuerten Events zurück.",
        },
    },
)
def list_timed_events(reqHandler, p, args, body):

    if args["verbose"]:
        return {"data": e_list_timed_events()}

    else:
        return {"data": list(event_dict.keys())}


@api_action(
    plugin,
    {
        "path": "event/*",
        "method": "GET",
        "params": [
            {
                "name": "event_name",
                "type": str,
                "f_name": {"EN": "Event name", "DE": "Eventname"},
            }
        ],
        "f_name": {"EN": "Get event", "DE": "Zeige Event"},
        "f_description": {
            "EN": "Returns a single event.",
            "DE": "Gibt ein einzelnes Event zurück.",
        },
    },
)
def get_timed_event(reqHandler, p, args, body):

    return {"data": e_get_timed_event(p[0])}


@api_action(
    plugin,
    {
        "path": "event/interval/*",
        "method": "POST",
        "params": [
            {
                "name": "event_name",
                "type": str,
                "f_name": {"EN": "Event name", "DE": "Eventname"},
            }
        ],
        "body": {
            "interval": {
                "type": int,
                "f_name": {"EN": "Interval", "DE": "Intervall"},
                "min": 1,
            },
            "enabled": {
                "type": bool,
                "f_name": {"EN": "Enabled", "DE": "Aktiviert"},
                "default": 1,
            },
            "repeat": {
                "type": bool,
                "f_name": {"EN": "Repeat", "DE": "Wiederholen"},
                "default": 0,
            },
            "method": {"type": str, "f_name": {"EN": "Method", "DE": "Methode"}},
            "path": {"type": str, "f_name": {"EN": "Path", "DE": "Pfad"}},
            "body": {
                "type": dict,
                "f_name": {"EN": "Body", "DE": "Body"},
                "default": {},
            },
        },
        "f_name": {"EN": "Create interval event", "DE": "Intervall Event erstellen"},
        "f_description": {
            "EN": "Creates a new interval Event.",
            "DE": "Erstellt eine neues intervallbasiertes Event.",
        },
    },
)
def create_timed_interval_event(reqHandler, p, args, body):
    auth = api_plugins()["auth"]
    current_user = auth.e_get_current_user()

    e_register_timed_interval_event(
        p[0],
        etv_action_request_template,
        [current_user, body["method"], body["path"], body["body"]],
        **body,
    )
    return {}


def i_format_static_params(key, value):
    static_format_dict = {
        "minute": {"type": list, "childs": {"type": int}},
        "hour": {"type": list, "childs": {"type": int}},
        "day_of_week": {"type": list, "childs": {"type": int}},
        "day_of_month": {"type": list, "childs": {"type": int}},
        "month": {"type": list, "childs": {"type": int}},
        "year": {"type": list, "childs": {"type": int}},
    }

    tmp_list = []
    for i, sub_val in enumerate(value.split(",")):
        tmp_list.append(sub_val.strip())

    value = try_convert_value(
        "body", "{}.{}".format(key, i), tmp_list, static_format_dict[key]
    )

    return value


@api_action(
    plugin,
    {
        "path": "event/static/*",
        "method": "POST",
        "params": [
            {
                "name": "event_name",
                "type": str,
                "f_name": {"EN": "Event name", "DE": "Eventname"},
            }
        ],
        "body": {
            "minute": {
                "type": str,
                "f_name": {"EN": "Minute", "DE": "Minute"},
                "default": "*",
            },
            "hour": {
                "type": str,
                "f_name": {"EN": "Hour", "DE": "Stunde"},
                "default": "*",
            },
            "day_of_week": {
                "type": str,
                "f_name": {"EN": "Day of week", "DE": "Tag der Woche"},
                "default": "*",
            },
            "day_of_month": {
                "type": str,
                "f_name": {"EN": "Day of Month", "DE": "Tag des Monats"},
                "default": "*",
            },
            "month": {
                "type": str,
                "f_name": {"EN": "Month", "DE": "Monat"},
                "default": "*",
            },
            "year": {
                "type": str,
                "f_name": {"EN": "Year", "DE": "Jahr"},
                "default": "*",
            },
            "enabled": {
                "type": bool,
                "f_name": {"EN": "Enabled", "DE": "Aktiviert"},
                "default": 1,
            },
            "repeat": {
                "type": bool,
                "f_name": {"EN": "Repeat", "DE": "Wiederholen"},
                "default": 0,
            },
            "method": {"type": str, "f_name": {"EN": "Method", "DE": "Methode"}},
            "path": {"type": str, "f_name": {"EN": "Path", "DE": "Pfad"}},
            "body": {
                "type": dict,
                "f_name": {"EN": "Body", "DE": "Body"},
                "default": {},
            },
        },
        "f_name": {"EN": "Create static event", "DE": "Statisches Event erstellen"},
        "f_description": {
            "EN": "Creates a new static Event.",
            "DE": "Erstellt eine neues statisches Event.",
        },
    },
)
def create_timed_static_event(reqHandler, p, args, body):
    auth = api_plugins()["auth"]
    current_user = auth.e_get_current_user()

    if body["minute"][0] == "*":
        body["minute"] = [-1]
    else:
        body["minute"] = i_format_static_params("minute", body["minute"])

    if body["hour"][0] == "*":
        body["hour"] = [-1]
    else:
        body["hour"] = i_format_static_params("hour", body["hour"])

    if body["day_of_week"][0] == "*":
        body["day_of_week"] = [-1]
    else:
        body["day_of_week"] = i_format_static_params("day_of_week", body["day_of_week"])

    if body["day_of_month"][0] == "*":
        body["day_of_month"] = [-1]
    else:
        body["day_of_month"] = i_format_static_params(
            "day_of_month", body["day_of_month"]
        )

    if body["month"][0] == "*":
        body["month"] = [-1]
    else:
        body["month"] = i_format_static_params("month", body["month"])

    if body["year"][0] == "*":
        body["year"] = [-1]
    else:
        body["year"] = i_format_static_params("year", body["year"])

    # args[key] = api_plugin.try_convert_value('args', key, value, action['args'][key])

    e_register_timed_static_event(
        p[0],
        etv_action_request_template,
        [current_user, body["method"].upper(), body["path"], body["body"]],
        **body,
    )
    return {}


@api_action(
    plugin,
    {
        "path": "event/*",
        "method": "DELETE",
        "params": [
            {
                "name": "event_name",
                "type": str,
                "f_name": {"EN": "Event name", "DE": "Eventname"},
            }
        ],
        "f_name": {"EN": "Delete event", "DE": "Event löschen"},
        "f_description": {"EN": "Deletes an event.", "DE": "Löscht ein Event."},
    },
)
def delete_timed_event(reqHandler, p, args, body):

    if not p[0] in event_dict:
        raise WebRequestException(400, "error", "TIME_EVENT_NOT_FOUND")

    event = event_dict[p[0]]
    event.setEnabled(0)
    del event_dict[p[0]]

    return {}


@api_action(
    plugin,
    {
        "path": "event/*/*",
        "method": "PUT",
        "params": [
            {
                "name": "event_name",
                "type": str,
                "f_name": {"EN": "Event name", "DE": "Eventname"},
            },
            {
                "name": "event_state",
                "type": bool,
                "f_name": {"EN": "Event state", "DE": "Eventstatus"},
            },
        ],
        "f_name": {"EN": "Set event state", "DE": "Eventstatus setzen"},
        "f_description": {
            "EN": "Enables/Disables an event.",
            "DE": "Aktiviert/Deaktiviert ein Event.",
        },
    },
)
def set_timed_event_state(reqHandler, p, args, body):

    if not p[0] in event_dict:
        raise WebRequestException(400, "error", "TIME_EVENT_NOT_FOUND")

    try:
        state = int(p[1])
    except:
        raise WebRequestException(
            400, "error", "GENERAL_VALUE_TYPE_ERROR", {"value": "state"}
        )

    event = event_dict[p[0]]

    if event.enabled == state:
        raise WebRequestException(400, "error", "TIME_STATE_ALREADY_SET")

    event.setEnabled(state)
    return {}
