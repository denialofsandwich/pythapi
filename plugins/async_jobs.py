#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: async_jobs.py
# Author:      Rene Fa
# Date:        10.01.2019
# Version:     0.8
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
import MySQLdb
from api_plugin import *
import threading
import time

plugin = api_plugin()
plugin.name = "job"
plugin.version = "0.8"
plugin.essential = False
plugin.info['f_name'] = {
    'EN': 'Asynchronous Jobs',
    'DE': 'Asynchrone Jobs'
}

plugin.info['f_description'] = {
    'EN': 'This plugin handles asynchronous jobs.',
    'DE': 'Dieses Plugin verwaltet asynchrone jobs.'
}

plugin.info['f_icon'] = {
    'EN': 'cached'
}

plugin.depends = []
plugin.config_defaults = {
    plugin.name: {
        'remove_on_termination': True
    }
}

plugin.translation_dict = {
    'JOB_JOB_NOT_FOUND': {
        'EN': 'Job not found.',
        'DE': 'Job nicht gefunden.'
    },
    'JOB_JOB_EXISTS': {
        'EN': 'Job already exists.',
        'DE': 'Job existiert bereits.'
    }

}

job_dict = {}

@api_external_function(plugin)
def e_default_termination_handler(job, e):
    log.error("The job {} crashed.".format(job.name), exc_info=e)
    job.status = 'crashed'

class AsyncJob():
    def __init__(self, name, func, func_args=[], func_kwargs={}, termination_handler=e_default_termination_handler):

        self.status = 'initializing'
        self.name = name
        self.func = func
        self.func_args = func_args
        self.func_kwargs = func_kwargs
        self.termination_handler = termination_handler
        self.return_value = None
        self.data = {}

        self.term_event = threading.Event()
        self.func_kwargs['_t_event'] = self.term_event
        self.func_kwargs['_job'] = self

        self.thread = threading.Thread(target=self.t_handler)
        self.thread.start()

    def t_handler(self):
        self.status = 'running'
        
        try:
            self.return_value = self.func(*self.func_args, **self.func_kwargs)

            if not self.term_event.is_set():
                self.status = 'done'

            else:
                self.status = 'terminated'

        except Exception as e:
            self.termination_handler(self, e)

        finally:
            if api_config()[plugin.name]['remove_on_termination']:
                try: del job_dict[self.name]
                except: pass
    
    def terminate(self):
        self.term_event.set()
        self.status = 'terminating'

@api_external_function(plugin)
def e_create_job(job_name, func, func_args=[], func_kwargs={}, termination_handler=e_default_termination_handler):
    if job_name in job_dict and (job_dict[job_name].status != 'done' and job_dict[job_name].status != 'terminated'):
        raise WebRequestException(400, 'error', 'JOB_JOB_EXISTS')

    job_dict[job_name] = AsyncJob(job_name, func, func_args, func_kwargs, termination_handler)
    return job_dict[job_name]

@api_external_function(plugin)
def e_get_raw_job(job_name):
    return job_dict[job_name]

def ir_safe_json_dump(d):
    if type(d) == dict:
        for k, v in d.items():
            d[k] = ir_safe_json_dump(d.get(k, {}))

    elif type(d) == list:
        for k, v in enumerate(d):
            d[k] = ir_safe_json_dump(v)
        
    elif not type(d) in [str, int, bool, dict, list, None]:
            d = str(d)

    return d

@api_external_function(plugin)
def e_get_job(job_name):
    return_json = {}
    
    job = job_dict[job_name]

    return_json['status'] = job.status
    return_json['func_name'] = job.func.__name__

    return_json['func_args'] = ir_safe_json_dump(job.func_args)
    return_json['func_kwargs'] = ir_safe_json_dump(job.func_kwargs)

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
    api_log().debug("Terminating all running jobs...")
    for job_name in job_dict:
        job_dict[job_name].terminate()

    for job_name in dict(job_dict):
        job_dict[job_name].thread.join()

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
        raise WebRequestException(400, 'error', 'JOB_JOB_NOT_FOUND')

    job_dict[p[0]].terminate()
    return {}

