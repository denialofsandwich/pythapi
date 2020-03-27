#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.casting

# TODO: recursive reimport
#   - Ermöglicht einfachere Plugin Syntax
#   - Und vielleicht kann man dann normale imports verwenden
#   - Dynamische Reimportierungsanomalien werden reduziert
#   - Eine Funktion die das macht soll hier bereitgestellt werden
#   - Beachte:
#       - Rekursionsschleifen unterbinden


log = None
module_dict = {}
plugin_dict = {}
serialized_plugin_list = []
inverse_dependency_table = {}
config = None
event_mapper = {}
broken_plugin_list = []

version = 0.1

event_data_skeleton = {
    "type": dict,
    "child": {
        "priority": {
            "type": int,
            "default": 10,
        },
    },
}


def init():
    global log
    global module_dict
    global plugin_dict
    global serialized_plugin_list
    global inverse_dependency_table
    global config
    global event_mapper

    log = None
    module_dict = {}
    plugin_dict = {}
    serialized_plugin_list = []
    inverse_dependency_table = {}
    config = None
    event_mapper = {
        'run': {
            "events": ["core.load"],
            "io_loop": True,
            "success_msg": "Pythapi successfuly started.",
        },
        'install': {
            "events": ["core.install"],
            "io_loop": True,
            "success_msg": "Pythapi successfuly installed.",
        },
        'uninstall': {
            "events": ["core.uninstall"],
            "io_loop": True,
            "success_msg": "Pythapi successfuly uninstalled.",
        },
        'reinstall': {
            "events": ["core.uninstall", "core.install"],
            "io_loop": True,
            "success_msg": "Pythapi successfuly reinstalled.",
        },
    }


class PythapiPlugin:
    def reinit(self):
        self.is_placed = False  # Placed in the serialized dependency list
        self.is_loaded = False  # Loading Event called
        self.error_code = 0

        # if "core.init" in self.events:
        #     warnings.warn("deprecated", DeprecationWarning)
        #     for i_event, data in self.events["core.init"]:
        #         i_event()

    def __init__(self, name):
        self.events = {}
        self.name = name
        self.module_name = name
        self.version = "0.0"
        self.essential = False
        self.info = {}
        self.config_defaults = {}
        self.depends = []

        self.reinit()


def external(plugin):
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

        if 'plugin_name' not in data:
            data['plugin_name'] = plugin.name

        plugin.events[event_name].append((f, data))
        return f

    return ap_generator


def sort_event(event_name, generate_empty=False) -> list:
    def empty(*args, **kwargs):
        pass

    sorting_dict = {10: []}
    for plugin_name in serialized_plugin_list:
        event_list = plugin_dict[plugin_name].events.get(event_name, [])
        if generate_empty and not event_list:
            sorting_dict[10].append((empty, {
                'name': "empty",
                'plugin_name': plugin_name,
                'priority': 10,
            }))

        for event_obj in event_list:
            data = core.casting.reinterpret(event_obj[1], **event_data_skeleton)

            priority = data.get('priority', 10)
            if priority not in sorting_dict:
                sorting_dict[priority] = []

            sorting_dict[priority].append(event_obj)

    sorted_event_list = []
    sorted_priorities = sorted(sorting_dict.keys())
    for priority in sorted_priorities:
        sorted_event_list.extend(sorting_dict[priority])

    return sorted_event_list
