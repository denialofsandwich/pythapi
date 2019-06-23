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
        self.defaults = {}
        self._dict = {}

    def __getitem__(self, key):
        return self._dict[key]

    def __setitem__(self, key, value):
        self._dict[key] = value

    def _apply_defaults(self):
        for section_name, section in list(self._dict.items()):
            for item_name, item in list(section.items()):

                operator = None
                if item_name[-1] in ['+']:
                    operator = item_name[-1]
                    unaltered_item_name = item_name
                    item_name = item_name[0:-1].strip()

                if operator:
                    print(item_name)

                try:
                    skeleton = self.defaults[section_name][item_name]
                except KeyError:
                    continue

                if operator == '+':
                    new_item = casting.cast_to(section[item_name], **skeleton) + casting.cast_to(item, **skeleton)
                    del self._dict[section_name][unaltered_item_name]
                else:
                    new_item = casting.cast_to(item, **skeleton)

                if operator:
                    print(new_item)

                self._dict[section_name][item_name] = new_item

    def as_dict(self):
        return self._dict

    def update(self, u):
        return _update(self._dict, u)

    def read_defaults(self, cfg_dict):
        readable_dict = {}

        for section_name, section in cfg_dict.items():
            if section_name not in readable_dict:
                readable_dict[section_name] = {}

            for item_name, item in section.items():
                if "default" not in item:
                    readable_dict[section_name][item_name] = None

                readable_dict[section_name][item_name] = item.get('default', None)

        self._dict = _update(readable_dict, self._dict)
        self.defaults = _update(self.defaults, cfg_dict)

        self._apply_defaults()

    def recursive_read(self, path):

        tmp_cfg = self.DictConfigParser()
        tmp_cfg.read(path)
        tmp_dict = tmp_cfg.parse_dict()
        self.update(tmp_dict)

        try:
            next_path = tmp_dict["core.general"]["include_files"]

            for i_path in glob.glob(next_path):
                i_cfg = PythapiConfigParser()
                i_cfg.recursive_read(i_path)
                self.update(i_cfg.as_dict())

        except KeyError:
            pass

        self._apply_defaults()

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
        for section_name, section in self.defaults.items():
            for item_name, default in section.items():
                if (
                    'default' not in default and
                    self._dict.get(section_name, {}).get(item_name, None) == None
                ):
                    raise ConfigNotSatisfiedException(default['type'], section_name, item_name)
