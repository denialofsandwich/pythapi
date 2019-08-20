#!/usr/bin/python3
# -*- coding: utf-8 -*-

log = None
module_dict = None
plugin_dict = None
serialized_plugin_list = None
inverse_dependency_table = None
config = None


def init():
    global log
    global module_dict
    global plugin_dict
    global serialized_plugin_list
    global inverse_dependency_table
    global config

    log = None
    module_dict = {}
    plugin_dict = {}
    serialized_plugin_list = []
    inverse_dependency_table = {}
    config = None


class PythapiPlugin:
    def reinit(self):
        self.is_placed = False  # Placed in the serialized dependency list
        self.is_loaded = False  # Loading Event called
        self.error_code = 0

        if "core.init" in self.events:
            for i_event, data in self.events["core.init"]:
                i_event()

    def __init__(self, name):
        self.events = {}
        self.name = name
        self.version = "0.0"
        self.essential = False
        self.info = {}
        self.config_defaults = {}
        self.depends = []

        self.reinit()


def external_function(plugin):
    def ap_generator(f):
        setattr(plugin, f.__name__, f)
        return f

    return ap_generator


def event(plugin, event_name, data=None, **kwargs):
    if data is None:
        data = {}

    def ap_generator(f):
        if event_name not in plugin.events:
            plugin.events[event_name] = []

        if 'name' not in data:
            data['name'] = f.__name__

        plugin.events[event_name].append((f, data))
        return f

    return ap_generator
