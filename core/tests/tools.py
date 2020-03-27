#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest

import core.main
import core.plugin_base

import argparse
import asyncio
import threading
import time


class CoreSystem:
    def __init__(self):
        args = argparse.Namespace()
        args.config = None
        args.config_parameter = []
        args.mode = 'run'
        args.no_fancy = False
        args.plugin = None
        args.reinstall = False
        args.verbosity = None
        self.args = args

        self.conf = {
            "core.general": {
                "loglevel": 6,
            }
        }

        self.event = None
        self.t = None

    def start(self):
        def use_core(a, e, c):
            try:
                asyncio.set_event_loop(asyncio.new_event_loop())
                core.plugin_base.broken_plugin_list.clear()
                core.main.run(a, e, c)
            except Exception as excp:
                e.set()
                print(excp)
                raise excp

        self.event = threading.Event()
        self.t = threading.Thread(target=use_core, args=(self.args, self.event, self.conf))
        self.t.start()

        self.event.wait()

        return self.t

    def stop(self):
        time.sleep(0.1)
        #with pytest.raises(SystemExit):
        try:
            core.main.termination_handler(None, None)
        except SystemExit:
            pass

        self.t.join()

    def __enter__(self):
        self.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
