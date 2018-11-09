#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: log_rotate.py
# Author:      Rene Fa
# Date:        26.04.2018
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
from api_plugin import *
import logging
import datetime
import glob
import re
import gzip
import shutil
import os

plugin = api_plugin()
plugin.name = "log_rotate"
plugin.version = "0.1"
plugin.essential = False
plugin.info['f_name'] = {
    'EN': 'Log rotate',
    'DE': 'Log Rotate'
}

plugin.info['f_description'] = {
    'EN': 'This Plugin automatically rotates, compresses and deletes logfiles.',
    'DE': 'Dieses Plugin rotiert, komprimiert und löscht automatisiert logfiles.'
}

plugin.depends = [
    {
        'name': 'time',
        'required': True
    }
]

plugin.config_defaults = {
    plugin.name: {
        'rotate_hour': '2',
        'rotate_dayofweek': '*',
        'rotate_dayofmonth': '*',
        'rotate_month': '*',
        'rotate_year': '*',
        'compress_at': 7,
        'delete_at': 30
    }
}

@api_external_function(plugin)
def et_rotate_logfiles():
    config = api_config()
    log.debug("Rotating logfile...")

    log.fout.close()

    logfile_path = config['core.general']['logfile'].replace('[time]', datetime.datetime.now().strftime('%Y-%m-%d-%H-%M'))

    for handler in log.handlers:
        log.removeHandler(handler)

    log.fout = logging.FileHandler(logfile_path)
    log.fout.setLevel(logging.DEBUG)
    log.fout.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    log.addHandler(log.fout)
    log.addHandler(log.sout)

    logfile_template = config['core.general']['logfile'].replace('[time]', '*')
    log.debug(logfile_template)
    files = glob.glob(logfile_template) +glob.glob(logfile_template +'.gz')

    for i, filename in enumerate(reversed(sorted(files))):
        if (i+1) >= config['log_rotate']['delete_at']:
            os.remove(filename)
            continue

        if (i+1) >= config['log_rotate']['compress_at'] and filename[-3:] != '.gz':
            with open(filename, 'rb') as f_in, gzip.open(filename +'.gz', 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

            os.remove(filename)

def i_format_time_value(config, key, minv, maxv):
    if config[key] == "*":
        return [-1]

    try:
        val_list = []
        for val in config[key].split(','):
            val = int(config[key])

            if val > maxv or val < minv:
                raise ValueError("Error in Configuration: {} is out of range.".format(key))

            val_list.append(val)

        return val_list

    except:
        raise ValueError("Can't convert {} to a number".format(key))

@api_event(plugin, 'load')
def load():
    config = api_config()[plugin.name]

    # Create scheduled timer
    time_dict = {
        'minute': [0],
        'hour': i_format_time_value(config, 'rotate_hour', 0, 23),
        'day_of_week': i_format_time_value(config, 'rotate_dayofweek', 1, 7),
        'day_of_month': i_format_time_value(config, 'rotate_dayofmonth', 1, 31),
        'month': i_format_time_value(config, 'rotate_month', 1, 12),
        'year': i_format_time_value(config, 'rotate_year', 0, 9999)
    }

    time_plugin = api_plugins()['time']
    time_plugin.e_register_timed_static_event('_log_rotate_job', et_rotate_logfiles, [], enabled=1, repeat=1, **time_dict)

    return 1
