#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import pathlib
import importlib
import importlib.util
import asyncio
import copy

from . import fancy_logs
from . import parse_conf
from . import defaults
from . import plugin_base
from . import casting


version = 2.0
loop = None
loaded_event = None
log = None
terminated = True

# TODO: Plugins auf die neusten Änderungen anpassen
#   - web.init in core.declare ändern


def terminate_application(error_msg=None, exc_info=None, soft=False):
    global terminated
    if terminated:
        return

    if loaded_event is not None:
        loaded_event.set()

    for event, data in plugin_base.sort_event('core.terminate'):
        if not plugin_base.plugin_dict[data['plugin_name']].is_loaded:
            continue

        event()

    if loop is not None:
        loop.call_soon_threadsafe(loop.stop)

    if log is not None:
        log.set_indent(-999)

        if error_msg is not None:
            log.critical(error_msg, exc_info=exc_info)
            terminated = True
            if not soft:
                sys.exit(1)

    terminated = True
    if not soft:
        log.info("Pythapi terminated.")
        sys.exit(0)


def termination_handler(signal, frame):
    print()
    terminate_application()


def r_mark_broken_dependencies(plugin_name, plugin_dict, inverse_dependency_table, depth=0):
    if depth > len(plugin_dict):
        terminate_application("Loop in dependency tree!")

    try:
        plugin = plugin_dict[plugin_name]
    except KeyError:
        return

    if plugin.error_code == 1:
        return

    for id_name, id_required in inverse_dependency_table[plugin_name]:
        if id_required is False:
            continue

        log.error("{} is missing {}.".format(id_name, plugin_name))
        r_mark_broken_dependencies(
            id_name,
            plugin_dict,
            inverse_dependency_table,
            depth+1
        )

    plugin.error_code = 1


def serialize_plugin_hierarchy(plugin_dict, inverse_dependency_table, single_plugin_name=None):
    # Step 1: Traverse dependency tree
    def r_traverse_dependencies(i_plugin, i_depth=0):
        if i_depth > len(plugin_dict):
            terminate_application("Loop in dependency tree!")

        if i_plugin.is_placed:
            return []

        i_serialized_list = []
        for i_dependency in i_plugin.depends:
            if not i_dependency['required']:
                continue

            try:
                i_serialized_list.extend(
                    r_traverse_dependencies(
                        plugin_dict[i_dependency['name']],
                        i_depth+1
                    )
                )
            except KeyError:
                log.error("{} is missing {}.".format(i_plugin.name, i_dependency['name']))
                r_mark_broken_dependencies(
                    i_plugin.name,
                    plugin_dict,
                    inverse_dependency_table
                )

        i_serialized_list.append(i_plugin.name)
        i_plugin.is_placed = True
        return i_serialized_list

    for plugin_name in plugin_dict:
        plugin_dict[plugin_name].is_placed = 0

    serialized_list = []
    if single_plugin_name:
        serialized_list.extend(
            r_traverse_dependencies(plugin_dict[single_plugin_name])
        )
    else:
        for k, plugin in plugin_dict.items():
            serialized_list.extend(
                r_traverse_dependencies(plugin)
            )

    return serialized_list


def run(args, event=None, config_dict=None):
    global terminated
    global log
    global loop
    global loaded_event
    loaded_event = event

    def deactivate_plugins_and_restart(plugin_names, filename=False):
        global terminated
        global log
        nonlocal args
        nonlocal event
        nonlocal config_dict

        if filename is False:
            plugin_filenames = []
            for i_plugin_name in plugin_names:
                i_plugin = plugin_base.plugin_dict[i_plugin_name]
                if i_plugin.essential is True:
                    terminate_application("{} is marked as essential.".format(i_plugin_name))

                plugin_filenames.append(plugin_base.plugin_dict[i_plugin_name].module_name)
        else:
            plugin_filenames = plugin_names

        plugin_base.broken_plugin_list.extend(plugin_filenames)

        log.warning("Restarting pythapi without broken plugins...")
        terminate_application(soft=True)
        return run(args, event, config_dict)

    if not terminated:
        print("Pythapi is already running!")

        if loaded_event is not None:
            loaded_event.set()

        return

    terminated = False
    # Reset plugin_base variables
    plugin_base.init()

    # Read configuration files
    config_parser = parse_conf.PythapiConfigParser()

    config_file = args.config or [defaults.config_base_path]

    for config in config_file:
        config_parser.recursive_read(config)

    if config_dict:
        if type(config_dict) is dict:
            config_dict = [config_dict]

        for config in config_dict:
            config_parser.recursive_read_dict(config)

    config_parser.read_list(args.config_parameter)

    config_parser.read_defaults(defaults.config_defaults)
    plugin_base.config = config_parser

    config_cgen = config_parser["core.general"]

    # Initialize fancy_logs
    log = fancy_logs.FancyLogger(
        not (not config_cgen["colored_logs"] or args.no_fancy),
        args.verbosity or config_cgen["loglevel"],
        config_cgen["show_timestamp"] or args.no_fancy,
        config_cgen["file_logging_enabled"],
        config_cgen["logfile"],
        )
    plugin_base.log = log
    log.create_loglevel('success', 25, pretty_format="\033[93m[\033[32m{:^8}\033[0m\033[93m]\033[32m{}")

    log.debug("Using {} as configuration file.".format(str(config_file)))

    log.info("Start importing plugins...")
    # Change directory to pythapi root dir
    os.chdir(str(pathlib.Path(__file__).parents[1]))

    log.set_indent(1)
    # Add additional plugin paths
    plugin_search_paths = ['plugins'] + config_cgen['additional_plugin_paths']
    for path in plugin_search_paths:
        sys.path.append(path)

    # Import enabled plugins
    tmp_plugin_name_list = config_cgen['enabled_plugins']
    tmp_remaining_pn_list = copy.copy(tmp_plugin_name_list)
    for plugin_filename in list(tmp_plugin_name_list):
        if not importlib.util.find_spec(plugin_filename):
            continue

        if plugin_filename in plugin_base.broken_plugin_list:
            tmp_remaining_pn_list.remove(plugin_filename)
            continue

        if plugin_filename not in sys.modules:
            log.info("Importing {}...".format(plugin_filename))
        else:
            log.debug("{} already imported".format(plugin_filename))
        tmp_remaining_pn_list.remove(plugin_filename)
        try:
            module = importlib.import_module(plugin_filename)
            module.plugin.module_name = plugin_filename
            plugin_base.module_dict[plugin_filename] = module

            config_parser.read_defaults(module.plugin.config_defaults)
            module.plugin.reinit()

        except Exception as e:
            log.error("Error while importing {}".format(plugin_filename), exc_info=e)
            return deactivate_plugins_and_restart([plugin_filename], filename=True)

    for plugin_name in tmp_remaining_pn_list:
        log.warning("Can't find plugin: {}".format(plugin_name))

    log.set_indent(-1)

    # Build plugin_dict and inverse_dependency_table
    plugin_dict = {}
    inverse_dependency_table = {}
    for k, module in plugin_base.module_dict.items():
        plugin_name = module.plugin.name
        plugin_dict[plugin_name] = module.plugin

        inverse_dependency_table[plugin_name] = set()

        cfg = config_parser.as_dict()
        if plugin_name in cfg and 'essential' in cfg[plugin_name]:
            module.plugin.essential = casting.reinterpret(cfg[plugin_name]['essential'], bool)

    for plugin_name, plugin in plugin_dict.items():
        for dependency in plugin.depends:
            try:
                inverse_dependency_table[dependency['name']].add((plugin_name, dependency['required']))
            except KeyError:
                continue

    plugin_base.plugin_dict = plugin_dict
    plugin_base.inverse_dependency_table = inverse_dependency_table

    # Build serialized dependency list
    log.debug("Serialize dependency tree...")
    serialized_plugin_list = serialize_plugin_hierarchy(
        plugin_dict,
        inverse_dependency_table,
        args.plugin
    )
    plugin_base.serialized_plugin_list = serialized_plugin_list

    # Check if there are any unmet dependencies
    broken_dependency_list = []
    for plugin_name, plugin in plugin_base.plugin_dict.items():
        if plugin.error_code == 1:
            broken_dependency_list.append(plugin.module_name)

    if len(broken_dependency_list) != 0:
        return deactivate_plugins_and_restart(broken_dependency_list)

    # Start running the pre_load events
    sorted_declare_events = plugin_base.sort_event('core.declare')
    log.info("Running {} core.declare events".format(len(sorted_declare_events)))
    log.set_indent(1)
    for f, data in sorted_declare_events:
        plugin_name = data['plugin_name']
        log.debug("Running {} from {}...".format('core.declare', plugin_name))
        log.set_indent(1)
        try:
            f()
        except Exception as e:
            log.error("An error occured while executing core.declare from {}:".format(plugin_name), exc_info=e)
            return deactivate_plugins_and_restart([plugin_name])
        log.set_indent(-1)
    log.set_indent(-1)

    # From here, all additional runmodes should be added
    selected_event = plugin_base.event_mapper.get(args.mode, None)
    if not selected_event:
        terminate_application("Unknown runmode! Supported modes: {}".format(', '.join(plugin_base.event_mapper.keys())))

    # Start running all runmode events defined in plugin_base.event_mapper
    for event_name in selected_event['events']:
        sorted_load_events = plugin_base.sort_event(event_name, generate_empty=True)
        log.info("Running {} {} events".format(len(sorted_load_events), event_name))
        log.set_indent(1)
        for f, data in sorted_load_events:
            plugin_name = data['plugin_name']
            log.debug("Running {} from {}...".format(event_name, plugin_name))
            log.set_indent(1)
            try:
                f()
                plugin_base.plugin_dict[plugin_name].is_loaded = True
            except Exception as e:
                log.error("An error occured while executing {} from {}:".format(event_name, plugin_name), exc_info=e)
                return deactivate_plugins_and_restart([plugin_name])
            log.set_indent(-1)
        log.set_indent(-1)

    log.log(25, selected_event.get('success_msg', "Done."))

    if selected_event.get('io_loop', False):
        log.set_indent(-999)
        log.info("Entering main loop...")
        loop = asyncio.get_event_loop()

        if loaded_event is not None:
            loaded_event.set()

        loop.run_forever()
