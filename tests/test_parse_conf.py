#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest
import core.parse_conf as p
import core.defaults
import core.casting


def test_read_base():
    config_parser = p.PythapiConfigParser()
    config_parser.read_defaults(core.defaults.config_defaults)
    config_parser.recursive_read("tests/configs/read_basic.ini")
    config_cgen = config_parser['core.general']

    assert type(config_cgen['loglevel']) == int
    assert config_cgen['loglevel'] == 6

    assert type(config_cgen['enabled_plugins']) == list
    assert config_cgen['enabled_plugins'] == ['debug', 'debug2', 'debug3']

    assert type(config_cgen['file_logging_enabled']) == bool
    assert config_cgen['file_logging_enabled'] is False


def test_read_list():
    config_parser = p.PythapiConfigParser()
    config_parser.read_defaults(core.defaults.config_defaults)
    config_parser.read_list([
        "core.general.loglevel=1",
        "core.general.logfile=space between.log",
    ])
    config_cgen = config_parser['core.general']

    assert type(config_cgen['loglevel']) == int
    assert config_cgen['loglevel'] == 1

    assert type(config_cgen['logfile']) == str
    assert config_cgen['logfile'] == "space between.log"


def test_read_string():
    cfg = """
        [core.general]
        loglevel = 3
    """

    config_parser = p.PythapiConfigParser()
    config_parser.read_defaults(core.defaults.config_defaults)
    config_parser.recursive_read_string(cfg)
    config_cgen = config_parser['core.general']

    assert type(config_cgen['loglevel']) == int
    assert config_cgen['loglevel'] == 3


def test_read_dict():
    cfg = {
        "core.general": {
            "loglevel": 2
        }
    }

    config_parser = p.PythapiConfigParser()
    config_parser.read_defaults(core.defaults.config_defaults)
    config_parser.recursive_read_dict(cfg)
    config_cgen = config_parser['core.general']

    assert type(config_cgen['loglevel']) == int
    assert config_cgen['loglevel'] == 2


def test_set_value():
    cfg = """
        [core.general]
        loglevel = 3
    """

    config_parser = p.PythapiConfigParser()
    config_parser.read_defaults(core.defaults.config_defaults)
    config_parser.recursive_read_string(cfg)
    config_cgen = config_parser['core.general']

    config_cgen['loglevel'] = 5

    assert type(config_cgen['loglevel']) == int
    assert config_cgen['loglevel'] == 5


def test_read_recursive():
    cfg = """
        [core.general]
        loglevel = 3
        include_files = tests/configs/read_basic.ini
    """

    config_parser = p.PythapiConfigParser()
    config_parser.read_defaults(core.defaults.config_defaults)
    config_parser.recursive_read_string(cfg)
    config_cgen = config_parser['core.general']

    assert type(config_cgen['loglevel']) == int
    assert config_cgen['loglevel'] == 6


def test_handle_operator_append():
    cfg = """
        [core.general]
        enabled_plugins = debug, debug2, debug3
        enabled_plugins += debug4
        
        logfile = test
        logfile += 2
    """

    config_parser = p.PythapiConfigParser()
    config_parser.read_defaults(core.defaults.config_defaults)
    config_parser.recursive_read_string(cfg)
    config_cgen = config_parser['core.general']

    print(config_parser.as_dict())

    assert type(config_cgen['enabled_plugins']) == list
    assert config_cgen['enabled_plugins'] == ['debug', 'debug2', 'debug3', 'debug4']

    assert type(config_cgen['logfile']) == str
    assert config_cgen['logfile'] == "test2"


def test_verify():
    cfg = """
        [core.general]
        loglevel = 3
        who_am_i = pls tell me
    """

    cfg_defaults = {
        'core.general': {
            'loglevel': {
                'type': int,
            },
            'im_not_there': {
                'type': str,
            }
        }
    }

    config_parser = p.PythapiConfigParser()
    config_parser.read_defaults(cfg_defaults)

    with pytest.raises(core.casting.MissingValueError):
        config_parser.recursive_read_string(cfg)


