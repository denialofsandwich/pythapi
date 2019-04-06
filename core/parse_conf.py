#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi
# Author:      Rene Fa
# Date:        03.04.2019
#
# Copyright:   Copyright (C) 2019  Rene Fa
#
#              This program is free software: you can redistribute it and/or modify
#              it under the terms of the GNU Affero General Public License as published by
#              the Free Software Foundation, either version 3 of the License, or any later version.
#
#              This program is distributed in the hope that it will be useful,
#              but WITHOUT ANY WARRANTY; without even the implied warranty of
#              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#              GNU Affero General Public License for more details.
#
#              You should have received a copy of the GNU Affero General Public License
#              along with this program.  If not, see https://www.gnu.org/licenses/agpl-3.0.de.html.
#

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


# TODO: Add verify_configuration method
class ConfigNotSatisfiedException(Exception):
    def __init__(self, should_type, section_name, item_name):
        msg = 'Missing configuration value in: "{}" at: "{}". Should be of type: "{}"'.format(
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

    def _apply_defaults(self):
        for section_name, section in list(self._dict.items()):
            for item_name, item in list(section.items()):

                try:
                    skeleton = self.defaults[section_name][item_name]
                except KeyError:
                    continue

                new_item = casting.cast_to(item, **skeleton)
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

                readable_dict[section_name][item_name] = item["default"]

        self._dict = _update(readable_dict, self._dict)
        self.defaults = cfg_dict

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
