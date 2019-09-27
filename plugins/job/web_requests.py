#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base
from . import header
from . import base


@core.plugin_base.event(header.plugin, 'web.init')
def web_init(event_data):

    @core.plugin_base.event(header.plugin, 'web.request', {
        "path": "/list",
        "method": "GET",
    })
    def list_jobs_request(**kwargs):
        name_list = []
        for job in list(base.JobObject.job_list):
            name_list.append(job.name)

        return {
            "data": name_list,
        }
