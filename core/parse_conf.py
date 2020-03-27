#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import glob
import collections
from . import casting


def _update(d, u):
    for k, v in u.items():
        if isinstance(v, collections.Mapping) and type(d.get(k, None)) is not str:
            d[k] = _update(d.get(k, {}), v)
        else:
            d[k] = v
    return d


def _pre_operator_formatter(val, **kwargs):

    for item_name in val:
        if item_name[-1] not in ['+']:
            continue

        target_item_name = item_name[0:-1].strip()
        val[item_name] = casting.reinterpret(val[item_name], **kwargs['child'][target_item_name])

    return val


def _post_operator_formatter(val, **kwargs):

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
            'verify': True,
        }
        self._dict = {}
        self._unparsed_conf = {}

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
        conf_slice = {}
        for section_name, section in cfg_dict.items():
            conf_slice[section_name] = dict(self._unparsed_conf.get(section_name, {}))

            formatted_defaults[section_name] = {
                'type': dict,
                'default': {},
                'child': section,
                'pre_format': _pre_operator_formatter,
                'post_format': _post_operator_formatter,
            }

        conf_slice = casting.reinterpret(conf_slice, **{
            'type': dict,
            'child': formatted_defaults,
            'default': {},
            'verify': True,
        })

        self.update(conf_slice)
        self.defaults['child'] = _update(self.defaults['child'], formatted_defaults)

    def _process_config(self, config_dict):
        _update(self._unparsed_conf, config_dict)

        self.update(config_dict)

        try:
            next_path = config_dict["core.general"]["include_files"]

            for i_path in glob.glob(next_path):
                i_cfg = PythapiConfigParser()
                i_cfg.recursive_read(i_path)
                i_cfg_dict = i_cfg.as_dict()

                _update(self._unparsed_conf, i_cfg_dict)
                self.update(i_cfg_dict)

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

        _update(self._unparsed_conf, d)
        #self.update(d)
        self._apply_defaults()
