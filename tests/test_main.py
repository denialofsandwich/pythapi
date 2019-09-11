#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest

import core.main

import argparse
import threading
import asyncio
import re
import collections


base_data = collections.namedtuple('base_data', ['args', 'conf'])


# Quelle: https://mail.python.org/pipermail/python-list/2014-June/673646.html
def start_core(args, conf):
    def use_core(a, e, c):

        asyncio.set_event_loop(asyncio.new_event_loop())
        core.main.run(a, e, c)

    event = threading.Event()
    t = threading.Thread(target=use_core, args=(args, event, conf))
    t.start()

    event.wait(5)

    return t


def stop_core(t):

    with pytest.raises(SystemExit):
        core.main.termination_handler(None, None)

    t.join()


@pytest.fixture(scope='function')
def base_config():
    args = argparse.Namespace()
    args.config = None
    args.config_parameter = []
    args.mode = 'run'
    args.no_fancy = False
    args.plugin = None
    args.reinstall = False
    args.verbosity = None

    conf = {
        "core.general": {
            "loglevel": 6,
            "additional_plugin_paths": "tests/plugins",
            "enabled_plugins": "debug, debug2, debug3",
        },
        "debug2": {
            "enabled_plugins": "lolo, lili, lulu",
        },
    }

    return base_data(args, conf)


def test_plain_start(capsys, base_config):
    t = start_core(base_config.args, base_config.conf)
    stop_core(t)

    logs = capsys.readouterr().out
    print(logs)

    assert len(re.findall(re.escape("Triggering core.load event for debug{}...".format(1)), logs)) == 1
    assert len(re.findall(re.escape("Triggering core.load event for debug{}...".format(3)), logs)) == 1

    assert len(re.findall(re.escape("TERMINATATA"), logs)) == 1

    assert len(re.findall(r'ERROR|CRITICAL', logs)) == 0


# debug2 should throw an error, because it needs debug3 to load
def test_broken_dependency(capsys, base_config):
    base_config.conf['core.general']['enabled_plugins'] = "debug, debug2, tete"

    t = start_core(base_config.args, base_config.conf)
    stop_core(t)

    # Notice the missing Plugin "tete"

    logs = capsys.readouterr().out
    print(logs)

    assert len(re.findall(re.escape("Can't find plugin: tete"), logs)) == 1
    assert len(re.findall(r'ERROR', logs)) == 1


def test_r_mark_broken_dependencies(capsys, base_config):

    # Test loop detector
    core.main.r_mark_broken_dependencies(None, {}, None, depth=1)

    # Test behavior if plugin doesn't exist
    core.main.r_mark_broken_dependencies("a", {}, None)

    # Flush sysout
    print(capsys.readouterr())

    base_config.conf['core.general']['enabled_plugins'] = "debug2, debug3"
    t = start_core(base_config.args, base_config.conf)

    logs = capsys.readouterr().out
    print(logs)

    for i in range(2, 4):
        assert len(re.findall(re.escape("Disabling debug{} due to an error".format(i)), logs)) == 1

    assert len(re.findall(r'ERROR', logs)) == 1

    stop_core(t)


def test_serialize_plugin_hierarchy_loop_detection(capsys, base_config):
    base_config.conf['core.general']['enabled_plugins'] = "broken_loop"

    t = start_core(base_config.args, base_config.conf)
    t.join()

    logs = capsys.readouterr().out
    assert len(re.findall(r'CRITICAL', logs)) == 1


def test_run_single_plugin(capsys, base_config):
    base_config.args.plugin = "debug1"

    t = start_core(base_config.args, base_config.conf)
    stop_core(t)

    logs = capsys.readouterr().out
    print(logs)


def test_run_twice(capsys, base_config):
    t = start_core(base_config.args, base_config.conf)
    capsys.readouterr()

    t2 = start_core(base_config.args, base_config.conf)
    logs = capsys.readouterr().out
    print(logs)
    assert len(re.findall(re.escape("Pythapi is already running!"), logs)) == 1

    stop_core(t)


def test_read_config_file(capsys, base_config):
    base_config.args.config = "tests/configs/read_from_run.ini"

    t = start_core(base_config.args, None)
    stop_core(t)

    logs = capsys.readouterr().out
    print(logs)
    assert len(re.findall(r'ERROR|CRITICAL', logs)) == 0


def test_import_broken_plugin(capsys, base_config):
    base_config.conf['core.general']['enabled_plugins'] = "broken"

    t = start_core(base_config.args, base_config.conf)
    t.join()

    logs = capsys.readouterr().out
    print(logs)
    assert len(re.findall(r'CRITICAL', logs)) == 1


def test_import_broken_check_event(capsys, base_config):
    base_config.conf['core.general']['enabled_plugins +'] = "broken_check"

    t = start_core(base_config.args, base_config.conf)
    stop_core(t)

    logs = capsys.readouterr().out
    print(logs)
    assert len(re.findall(r'ERROR', logs)) == 1


def test_import_broken_load_event(capsys, base_config):
    base_config.conf['core.general']['enabled_plugins +'] = "broken_load"

    t = start_core(base_config.args, base_config.conf)
    stop_core(t)

    logs = capsys.readouterr().out
    print(logs)
    assert len(re.findall(r'ERROR', logs)) == 1


def test_uninstall(capsys, base_config):
    base_config.args.mode = "uninstall"

    t = start_core(base_config.args, base_config.conf)
    t.join()

    logs = capsys.readouterr().out
    print(logs)

    assert len(re.findall(re.escape("Triggering core.uninstall event for debug{}...".format(1)), logs)) == 1
    assert len(re.findall(re.escape("Triggering core.uninstall event for debug{}...".format(3)), logs)) == 1
    assert len(re.findall(r'ERROR', logs)) == 0


def test_install(capsys, base_config):
    base_config.args.mode = "install"

    t = start_core(base_config.args, base_config.conf)
    t.join()

    logs = capsys.readouterr().out
    print(logs)

    assert len(re.findall(re.escape("Triggering core.install event for debug{}...".format(1)), logs)) == 0
    assert len(re.findall(re.escape("Triggering core.install event for debug{}...".format(3)), logs)) == 0
    assert len(re.findall(r'ERROR', logs)) == 0
