#!/usr/bin/python3
# -*- coding: utf-8 -*-

log = None
module_dict = None
plugin_dict = None
serialized_plugin_list = None
inverse_dependency_table = None


def init():
    global log
    global module_dict
    global plugin_dict
    global serialized_plugin_list

    log = None
    module_dict = {}
    plugin_dict = {}
    serialized_plugin_list = []


class PythapiPlugin:
    def reinit(self):
        self.is_placed = False  # Placed in the serialized dependency list
        self.is_loaded = False  # Loading Event called
        self.error_code = 0

    def __init__(self, name):
        self.events = {}
        self.name = name
        self.version = "0.0"
        self.essential = False
        self.info = {}
        self.config_defaults = {}
        self.depends = []

        self.reinit()


def event(plugin, event_name, **kwargs):
    def ap_generator(f):
        plugin.events[event_name] = f
        return f

    return ap_generator
