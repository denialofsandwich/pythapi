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

    try:
        while not stop_event.is_set():
            #core.plugin_base.log.debug("AAA")
            stop_event.wait(2)
    finally:
        core.plugin_base.log.debug("WUWUWUWUWUWUWU")


@core.plugin_base.event(plugin, 'core.load')
def load():
    job = core.plugin_base.plugin_dict['job']

    core.plugin_base.log.debug("BBB")
    t = job.JobObject(name="test_job1", target=trd, daemon=True)
    # TODO: Implementiere das \/
    #t = job.JobObject(name="test_job1", target=trd, daemon=True).every(5).days.at("17:35")
    t.start()
