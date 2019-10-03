#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base

plugin = core.plugin_base.PythapiPlugin("job")
plugin.version = "1.0"
plugin.essential = False

plugin.info['f_name'] = {
    'EN': 'Jobs'
}

plugin.info['f_description'] = {
    'EN': 'Provides functionalities for background processes.',
    'DE': 'Stellt Funktionalitäten für Hintergrundprozesse bereit.'
}

plugin.depends = [
    {
        "name": "web",
        "required": False,
    }
]

plugin.config_defaults = {
    plugin.name: {},
}

plugin.JobNotFoundException = None
plugin.job_table = {}


def check_job_existence(val, **kwargs):
    if val not in plugin.job_table:
        raise plugin.JobNotFoundException(val)

    return val


plugin.web_template_table = {
    "job_obj": {
        "type": str,
        "regex": r"[_a-zA-Z0-9-]+",
        "pre_format": check_job_existence,
        "f_name": {
            "_tr": True,
            "EN": "Job name",
            "DE": "Job Name"
        }
    }
}
