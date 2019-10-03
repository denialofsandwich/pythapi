#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base
import core.casting

plugin = core.plugin_base.PythapiPlugin("debug_job")
plugin.version = "1.0"
plugin.essential = False

plugin.depends = [
    {
        'name': 'job',
        'required': True
    }
]

plugin.config_defaults = {}


def trd(**kwargs):
    stop_event = kwargs['_thread'].term_event
    stop_event.wait()


@core.plugin_base.external(plugin)
def create_basic_job(name):
    job = core.plugin_base.plugin_dict['job']

    t = job.JobObject(name=name, target=trd)
    t.start()


@core.plugin_base.external(plugin)
def create_scheduled_job(name):
    job = core.plugin_base.plugin_dict['job']

    t = job.JobObject(name=name, target=trd).every(2).days.at("03:35")
    t.start()


@core.plugin_base.external(plugin)
def remove_job(name):
    job = core.plugin_base.plugin_dict['job']
    job.job_table[name].remove()
