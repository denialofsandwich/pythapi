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
sys.path.append("..")
from api_plugin import * # Essential Plugin
import time
import datetime
from threading import Timer
import http.client
from base64 import b64encode
import json

plugin = api_plugin()
plugin.name = "time"
plugin.version = "0.1"
plugin.essential = False
plugin.info['f_name'] = {
    'EN': 'Time control',
    'DE': 'Zeitsteuerung'
}

plugin.info['f_description'] = {
    'EN': 'This plugin controls time-based events.',
    'DE': 'Dieses Plugin steuert zeitgestuerte Events.'
}

plugin.depends = [
    {
        'name': 'auth',
        'required': True
    },
    {
        'name': 'userdata',
        'required': True
    }
]

plugin.config_defaults = {}
plugin.translation_dict = {
    'TIME_EVENT_NOT_FOUND': {
        'EN': 'Event not found.',
        'DE': 'Event nicht gefunden.'
    },
    'TIME_EVENT_EXISTS': {
        'EN': 'Event already exist.',
        'DE': 'Event existiert bereits.'
    },
    'TIME_STATE_ALREADY_SET': {
        'EN': 'Event is already in target state.',
        'DE': 'Event ist bereits in Zielzustand.'
    }
}

event_dict = {}

class TimedIntervalEvent():
    def __init__(self,
                 name,
                 func,
                 func_args = [],
                 func_kwargs = {},
                 repeat = 0,
                 enabled = 1,
                 interval = 60):

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
            log.access('t_event {}'.format(self.name))
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
    def __init__(self,
                 name,
                 func,
                 func_args = [],
                 func_kwargs = {},
                 repeat = 0,
                 enabled = 1,
                 minute = [-1],
                 hour = [-1],
                 day_of_week = [-1],
                 day_of_month = [-1],
                 month = [-1],
                 year = [-1]):

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
        
        if (not self.i_check_time_unit(self.minute, time.minute) or
            not self.i_check_time_unit(self.hour, time.hour) or
            not self.i_check_time_unit(self.day_of_week, time.weekday()+1) or
            not self.i_check_time_unit(self.day_of_month, time.day) or
            not self.i_check_time_unit(self.month, time.month) or
            not self.i_check_time_unit(self.year, time.year)):

           self.i_recall_timer()
           return

        super().t_scheduler()

    def calc_time(self):
        wild_set = 0

        target_date = datetime.datetime.now()
        
        target_date = target_date.replace(microsecond = 10)
        target_date = target_date.replace(second = 0)
        target_date = target_date +datetime.timedelta(minutes=1)

        return (target_date - datetime.datetime.now()).total_seconds()

@api_external_function(plugin)
def e_get_timed_event(event_name):
    if not event_name in event_dict:
        raise WebRequestException(400, 'error', 'TIME_EVENT_NOT_FOUND')

    event = event_dict[event_name]

    return_json = {}
    return_json['name'] = event_name
    return_json['repeat'] = event.repeat
    return_json['enabled'] = event.enabled
    return_json['type'] = 'unknown'

    if type(event) == TimedIntervalEvent:
        return_json['type'] = 'interval'

        return_json['interval'] = event.interval
        

    elif type(event) == TimedStaticEvent:
        return_json['type'] = 'static'

        return_json['minute'] = event.minute
        return_json['hour'] = event.hour
        return_json['day_of_week'] = event.day_of_week
        return_json['day_of_month'] = event.day_of_month
        return_json['month'] = event.month
        return_json['year'] = event.year

    return return_json

@api_external_function(plugin)
def e_list_timed_events():
    return_json = []
    for event_name in event_dict:
        return_json.append(e_get_timed_event(event_name))

    return return_json

@api_external_function(plugin)
def e_register_timed_interval_event(event_name,
                                    func,
                                    func_args = [],
                                    func_kwargs = {},
                                    repeat = 0,
                                    enabled = 1,
                                    interval = 60,
                                    **kwargs):
    
    if event_name in event_dict:
        raise WebRequestException(400, 'error', 'TIME_EVENT_EXISTS')
    
    event_dict[event_name] = TimedIntervalEvent(event_name, func, func_args, func_kwargs, repeat, enabled, interval)

@api_external_function(plugin)
def e_register_timed_static_event(event_name,
                                  func,
                                  func_args = [],
                                  func_kwargs = {},
                                  repeat = 0,
                                  enabled = 1,
                                  minute = [-1],
                                  hour = [-1],
                                  day_of_week = [-1],
                                  day_of_month = [-1],
                                  month = [-1],
                                  year = [-1],
                                  **kwargs):
    
    if event_name in event_dict:
        raise WebRequestException(400, 'error', 'TIME_EVENT_EXISTS')
    
    event_dict[event_name] = TimedStaticEvent(event_name, func, func_args, func_kwargs, repeat, enabled, minute, hour, day_of_week, day_of_month, month, year)

@api_external_function(plugin)
def e_set_event_state(event_name, state):
    if not event_name in event_dict:
        raise WebRequestException(400, 'error', 'TIME_EVENT_NOT_FOUND')
    
    event_dict[event_name].setEnabled(state)

def test_func(text):
    log.debug("Text: {}".format(text))

@api_external_function(plugin)
def etv_action_request_template(current_user, method, path, body={}):
    
    auth = api_plugins()['auth']
    userdata = api_plugins()['userdata']

    try: 
        auth.e_get_user_token(current_user, '_timer_key')
        token = userdata.e_get_data(current_user, 'timer', 'user_token', 1)['user_token']

    except WebRequestException:
        token = auth.e_create_user_token(current_user, '_timer_key')
        userdata.e_write_data(current_user, 'timer', {'user_token': token}, 1)

    port = int(api_config()['core.web']['http_port'].split(',')[0])

    c = http.client.HTTPConnection("127.0.0.1", port)

    headers = { 'Authorization' : 'Bearer %s' %  token }

    c.request(method, path, json.dumps(body), headers=headers)
    res = c.getresponse()
    data = res.read()

    log.debug('{} {}'.format(api_environment_variables()['transaction_id'], data))

#@api_event(plugin, 'install')
#def install():
#    return 1
#
#@api_event(plugin, 'uninstall')
#def uninstall():
#    return 1
#
#@api_event(plugin, 'load')
#def load():
#    return 1

@api_event(plugin, 'terminate')
def terminate():
    
    log.debug('Terminating all scheduled timed events...')
    for event_name in event_dict:
        event = event_dict[event_name]
        event.setEnabled(0)

    return 1

list_and_dividable = ['minute','hour','day_of_week','day_of_month','month','year']
format_list = ['minute','hour','day_of_week','day_of_month','month','year','enabled','repeat','interval']

def i_check_range(name, body, min_val, max_val):
    if not name in body:
        return

    if len(body[name]) > 1 and not name in list_and_dividable:
        raise WebRequestException(400, 'error', 'GENERAL_VALUE_TYPE_ERROR', {
            'value': name
        })
        
    for value in body[name]:
        if value > max_val or value < min_val:
            raise WebRequestException(400, 'error', 'GENERAL_VALUE_RANGE_EXCEEDED', {
                'value': name,
                'min': min_val,
                'max': max_val
            })

def i_check_and_convert_value(name, body):
    
    if name in body:
        try:
            if body[name] == '*':
                body[name] = [-1]
            
            tmp_list = []
            for value in body[name].split(','):
                tmp_list.append(int(value))

            body[name] = tmp_list
        except:
            raise WebRequestException(400, 'error', 'GENERAL_VALUE_TYPE_ERROR', {
                'value': name
            })

@api_action(plugin, {
    'path': 'event/list',
    'method': 'GET',
    'f_name': {
        'EN': 'List events',
        'DE': 'Events auflisten'
    },

    'f_description': {
        'EN': 'Returns a list with all timed events.',
        'DE': 'Gibt eine Liste mit allen zeitgesteuerten Events zurück.'
    }
})
def list_timed_events(reqHandler, p, args, body):
    
    if 'verbose' in args and args['verbose'][0].decode("utf-8") == 'true':
        return {
            'data': e_list_timed_events()
        }

    else:
        return {
            'data': list(event_dict.keys())
        }

@api_action(plugin, {
    'path': 'event/*',
    'method': 'GET',
    'f_name': {
        'EN': 'Get event',
        'DE': 'Zeige Event'
    },

    'f_description': {
        'EN': 'Returns a single event.',
        'DE': 'Gibt ein einzelnes Event zurück.'
    }
})
def get_timed_event(reqHandler, p, args, body):
    
    return {
        'data': e_get_timed_event(p[0])
    }

@api_action(plugin, {
    'path': 'event/interval/*',
    'method': 'POST',
    'f_name': {
        'EN': 'Create interval event',
        'DE': 'Intervall Event erstellen'
    },

    'f_description': {
        'EN': 'Creates a new interval Event.',
        'DE': 'Erstellt eine neues intervallbasiertes Event.'
    }
})
def create_timed_interval_event(reqHandler, p, args, body):
    
    auth = api_plugins()['auth']
    current_user = auth.e_get_current_user()

    i_check_and_convert_value('interval', body)
    i_check_and_convert_value('enabled', body)
    i_check_and_convert_value('repeat', body)

    i_check_range('interval', body, 1, 99999999)
    i_check_range('enabled', body, 0, 1)
    i_check_range('repeat', body, 0, 1)

    for name in body:
        if name in format_list and not name in list_and_dividable:
            body[name] = body[name][0]

    if not 'body' in body:
        body['body'] = {}

    e_register_timed_interval_event(p[0], etv_action_request_template, [current_user, body['method'], body['path'], body['body']], **body)
    return {}

@api_action(plugin, {
    'path': 'event/static/*',
    'method': 'POST',
    'f_name': {
        'EN': 'Create static event',
        'DE': 'Statisches Event erstellen'
    },

    'f_description': {
        'EN': 'Creates a new static Event.',
        'DE': 'Erstellt eine neues statisches Event.'
    }
})
def create_timed_static_event(reqHandler, p, args, body):
    
    i_check_and_convert_value('minute', body)
    i_check_and_convert_value('hour', body)
    i_check_and_convert_value('day_of_week', body)
    i_check_and_convert_value('day_of_month', body)
    i_check_and_convert_value('month', body)
    i_check_and_convert_value('year', body)
    i_check_and_convert_value('enabled', body)
    i_check_and_convert_value('repeat', body)

    i_check_range('minute', body, -1, 59)
    i_check_range('hour', body, -1, 23)
    i_check_range('day_of_week', body, -1, 7)
    i_check_range('day_of_month', body, -1, 31)
    i_check_range('month', body, -1, 12)
    i_check_range('year', body, -1, 4000)
    i_check_range('enabled', body, 0, 1)
    i_check_range('repeat', body, 0, 1)
    
    for name in body:
        if not name in list_and_dividable:
            body[name] = body[name][0]

    if not 'body' in body:
        body['body'] = {}
    
    e_register_timed_static_event(p[0], etv_action_request_template, [current_user, body['method'], body['path'], body['body']], **body)
    return {}

@api_action(plugin, {
    'path': 'event/*',
    'method': 'DELETE',
    'f_name': {
        'EN': 'Delete event',
        'DE': 'Event löschen'
    },

    'f_description': {
        'EN': 'Deletes an event.',
        'DE': 'Löscht ein Event.'
    }
})
def delete_timed_event(reqHandler, p, args, body):
    
    if not p[0] in event_dict:
        raise WebRequestException(400, 'error', 'TIME_EVENT_NOT_FOUND')

    event = event_dict[p[0]]
    event.setEnabled(0)
    del event_dict[p[0]]

    return {}

@api_action(plugin, {
    'path': 'event/*/*',
    'method': 'PUT',
    'f_name': {
        'EN': 'Set event state',
        'DE': 'Eventstatus setzen'
    },

    'f_description': {
        'EN': 'Enables/Disables an event.',
        'DE': 'Aktiviert/Deaktiviert ein Event.'
    }
})
def set_timed_event_state(reqHandler, p, args, body):
    
    if not p[0] in event_dict:
        raise WebRequestException(400, 'error', 'TIME_EVENT_NOT_FOUND')

    try:
        state = int(p[1])
    except:
        raise WebRequestException(400, 'error', 'GENERAL_VALUE_TYPE_ERROR', {
            'value': 'state'
        })
    
    event = event_dict[p[0]]

    if event.enabled == state:
        raise WebRequestException(400, 'error', 'TIME_STATE_ALREADY_SET')

    event.setEnabled(state)
    return {}


@api_action(plugin, {
    'path': 'debug',
    'method': 'GET',
    'f_name': {
        'EN': 'Debug',
        'DE': 'Debug'
    },

    'f_description': {
        'EN': 'Debug',
        'DE': 'Debug'
    }
})
def debug1(reqHandler, p, args, body):
    

    return {
        'data': data
    }
