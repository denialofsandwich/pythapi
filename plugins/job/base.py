#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base
from . import header

import threading


@core.plugin_base.external(header.plugin)
class JobObject(threading.Thread):
    job_list = []

    def run(self) -> None:
        try:
            self.target(*self.args, **self.kwargs)
        except Exception as e:
            core.plugin_base.log.error("A Job crashed just now", exc_info=e)
        finally:
            JobObject.job_list.remove(self)

    def __init__(self, target=None, args=(), kwargs=None, **akwargs):
        kwargs = kwargs or {}
        kwargs['_thread'] = self

        self.term_event = threading.Event()
        self.target = target
        self.args = args
        self.kwargs = kwargs

        super().__init__(**akwargs)
        JobObject.job_list.append(self)

    def stop(self):
        self.term_event.set()
