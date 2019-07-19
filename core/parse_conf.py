#!/usr/bin/python3
# -*- coding: utf-8 -*-

import configparser
import glob
import collections
from . import casting


def _update(d, u):
    for k, v in u.items():
        if isinstance(v, collections.Mapping):
            d[k] = _update(d.get(k, {}), v)
        else:
            d[k] = v
    return d


def _pre_operator_formatter(val, t, **kwargs):

    for item_name in val:
        if item_name[-1] not in ['+']:
            continue

        target_item_name = item_name[0:-1].strip()
        val[item_name] = casting.reinterpret(val[item_name], **kwargs['child'][target_item_name])

    return val


def _post_operator_formatter(val, t, **kwargs):

    for item_name in list(val.keys()):
        if item_name[-1] not in ['+']:
            continue

        operator = item_name[-1]
        target_item_name = item_name[0:-1].strip()
        val[item_name] = casting.reinterpret(val[item_name], **kwargs['child'][target_item_name])

        if operator == '+':
            val[target_item_name] = val[target_item_name] + val[item_name]
            del val[item_name]

    return val


class ConfigNotSatisfiedException(Exception):
    def __init__(self, should_type, section_name, item_name):
        msg = 'Missing configuration value in: "{}.{}". Should be of type: "{}"'.format(
            section_name, item_name, should_type.__name__
        )
        Exception.__init__(self, msg)


class PythapiConfigParser:
    class DictConfigParser(configparser.ConfigParser):
        def parse_dict(self):
            d = dict(self._sections)
            for k in d:
                d[k] = dict(self._defaults, **d[k])
                d[k].pop("__name__", None)
            return d

    def __init__(self):
        self.defaults = {
            'type': dict,
            'child': {},
            'default': {},
        }
        self._dict = {}

    def __getitem__(self, key):
        return self._dict[key]

    def _apply_defaults(self):
        self._dict = casting.reinterpret(self._dict, **self.defaults)

    def as_dict(self):
        return self._dict

    def update(self, u):
        return _update(self._dict, u)

    def read_defaults(self, cfg_dict):
        formatted_defaults = {}
        for section_name, section in cfg_dict.items():
            formatted_defaults[section_name] = {
                'type': dict,
                'default': {},
                'child': section,
                'pre_format': _pre_operator_formatter,
                'post_format': _post_operator_formatter,
            }

        self.defaults['child'] = _update(self.defaults['child'], formatted_defaults)

        self._apply_defaults()

    def _process_config(self, config_dict):
        self.update(config_dict)

        try:
            next_path = config_dict["core.general"]["include_files"]

            for i_path in glob.glob(next_path):
                i_cfg = PythapiConfigParser()
                i_cfg.recursive_read(i_path)
                self.update(i_cfg.as_dict())

        except KeyError:
            pass

        self._apply_defaults()

    def recursive_read(self, path):
        tmp_cfg = self.DictConfigParser()
        tmp_cfg.read(path)
        tmp_dict = tmp_cfg.parse_dict()
        self._process_config(tmp_dict)

    def recursive_read_string(self, data):
        tmp_cfg = self.DictConfigParser()
        tmp_cfg.read_string(data)
        tmp_dict = tmp_cfg.parse_dict()
        self._process_config(tmp_dict)

    def recursive_read_dict(self, data):
        tmp_cfg = self.DictConfigParser()
        tmp_cfg.read_dict(data)
        tmp_dict = tmp_cfg.parse_dict()
        self._process_config(tmp_dict)

    def read_list(self, l):

        d = {}
        for p in l:
            s1 = p.split('=')
            s2 = s1[0].split('.')

            data = s1[1].strip()
            key = s2[-1]
            section = '.'.join(s2[0:-1])

            if section not in d:
                d[section] = {}

            d[section][key] = data

        self.update(d)
        self._apply_defaults()

    def verify(self):
        for section_name, section in self._dict.items():
            for item_name, item in section.items():
                if item is None:
                    raise ConfigNotSatisfiedException(
                        self.defaults['child'][section_name]['child'][item_name]['type'],
                        section_name,
                        item_name
                    )
