#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: info.py
# Author:      Rene Fa
# Date:        13.07.2018
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

import sys
sys.path.append("..")
import MySQLdb # MySQL
from api_plugin import * # Essential Plugin
from threading import Thread
import time

plugin = api_plugin()
plugin.name = "job"
plugin.version = "0.1"
plugin.essential = False
plugin.info['f_name'] = {
    'EN': 'Asynchronous Jobs',
    'DE': 'Asynchrone Jobs'
}

plugin.info['f_description'] = {
    'EN': 'This plugin handles asynchronous jobs.',
    'DE': 'Dieses Plugin verwaltet asynchrone jobs.'
}

plugin.depends = [
    {
        'name': 'auth',
        'required': False
    }
]

plugin.config_defaults = {}

plugin.translation_dict = {
    'JOB_NOT_FOUND': {
        'EN': 'Job not found.',
        'DE': 'Job nicht gefunden.'
    }
}

job_dict = {}

class AsyncJob():
    def __init__(self, name, func, func_args=[], func_kwargs={}):

        self.status = 'initializing'
        self.name = name
        self.func = func
        self.func_args = func_args
        self.func_kwargs = func_kwargs
        self.return_value = None
        self.data = {}

        job_dict[name] = self

        self.thread = Thread(target=self.t_handler)
        self.thread.start()

    def t_handler(self):
       self.status = 'running'
       api_log().debug("{} is now running.".format(self.name))
       self.return_value = self.func(*self.func_args, **self.func_kwargs)
       self.status = 'done'
       api_log().debug("{} is done.".format(self.name))
    
#    def terminate(self):
#        self.thread.cancel()
#        del job_dict[self.name]

@api_external_function(plugin)
def e_create_job(job_name, func, func_args=[], func_kwargs={}):
    AsyncJob(job_name, func, func_args, func_kwargs)

@api_external_function(plugin)
def e_get_job(job_name):
    return_json = {}
    
    job = job_dict[job_name]

    return_json['status'] = job.status
    return_json['func_name'] = job.func.__name__
    return_json['func_args'] = job.func_args
    return_json['func_kwargs'] = job.func_kwargs

    return_json['data'] = job.data
    return_json['return_value'] = job.return_value

    return return_json

@api_external_function(plugin)
def e_list_jobs():
    return_json = []
    for job_name in job_dict:
        i_entry = e_get_job(job_name)
        i_entry['name'] = job_name

        return_json.append(i_entry)

    return return_json

@api_event(plugin, 'terminate')
def terminate():
    return 1

@api_action(plugin, {
    'path': 'list',
    'method': 'GET',
    'args': {
        'verbose': {
            'type': bool,
            'default': False,
            'f_name': {
                'EN': "Verbose",
                'DE': "Ausführlich"
            }
        }
    },
    'f_name': {
        'EN': 'List jobs',
        'DE': 'Zeige alle Jobs'
    },

    'f_description': {
        'EN': 'Returns a list of all jobs.',
        'DE': 'Gibt eine Liste mit allen jobs zurück.'
    }
})
def list_jobs(reqHandler, p, args, body):
    
    if args['verbose']:
        return {
            'data': e_list_jobs()
        }
    
    else:
        return {
            'data': list(job_dict.keys())
        }

@api_action(plugin, {
    'path': '*',
    'method': 'GET',
    'params': [
        {
            'name': "job_name",
            'type': str,
            'f_name': {
                'EN': "Job Name",
                'DE': "Job Name"
            }
        }
    ],
    'f_name': {
        'EN': 'Get job',
        'DE': 'Zeige Job'
    },

    'f_description': {
        'EN': 'Returns a single job.',
        'DE': 'Gibt einen einzelnen Job zurück.'
    }
})
def get_job(reqHandler, p, args, body):
    return {
        'data': e_get_job(p[0])
    }

def test_func(val):
    print("Das ist: {}".format(val))
    time.sleep(45)

@api_action(plugin, {
    'path': '*',
    'method': 'POST',
    'params': [
        {
            'name': "job_name",
            'type': str,
            'f_name': {
                'EN': "Job Name",
                'DE': "Job Name"
            }
        }
    ],
    'f_name': {
        'EN': 'Add new certificate',
        'DE': 'Neues Zertifikat hinzufügen'
    },

    'f_description': {
        'EN': 'Adds a new certificate to the certpool and request it.',
        'DE': 'Fügt ein neues Zertifikat zum Pool hinzu und fordert es an.'
    }
})
def add_certificate(reqHandler, p, args, body):
    e_create_job(p[0], test_func, ["Teststring"])
    return {}

@api_action(plugin, {
    'path': '*',
    'method': 'DELETE',
    'params': [
        {
            'name': "job_name",
            'type': str,
            'f_name': {
                'EN': "Job Name",
                'DE': "Job Name"
            }
        }
    ],
    'f_name': {
        'EN': 'Terminate job',
        'DE': 'Job beenden'
    },

    'f_description': {
        'EN': 'Terminates a job and removes it from the job list.',
        'DE': 'Beendet einen Job und entfernt ihn von der Jobliste.'
    }
})
def terminate_job(reqHandler, p, args, body):
    if not p[0] in job_dict:
        raise WebRequestException(400, 'error', 'JOB_NOT_FOUND')

    #job_dict[p[0]].terminate()
    return {}

