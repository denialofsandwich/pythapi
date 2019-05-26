#!/usr/bin/python3
# -*- coding: utf-8 -*-


log = None


class PythapiPlugin:
    def __init__(self):
        self.events = {}
        self.name = None
        self.version = "0.0"
        self.essential = False
        self.info = {}


def event(plugin, event_name, **kwargs):
    def ap_generator(f):
        plugin.events[event_name] = f
        return f

    return ap_generator
