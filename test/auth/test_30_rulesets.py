#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: unittests
# Author:      Rene Fa
# Date:        08.02.2019
# Version:     0.1
#
# Copyright:   Copyright (C) 2018  Rene Fa
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
# Usage:       PYTHONPATH=. pytest --cov .
#       Use in project root directory
#
# Requires:    pytest coverage pytest-cov
#

import pytest
import json


def test_merge_permissions(pythapi):
    auth = pythapi.module_dict["auth"]

    # Test 1
    ruleset = {
        "permissions": ["auth.user.get.all", "data.read"],
        "inherit": ["default"],
    }
    default_ruleset = auth.e_get_role("auth_default")["ruleset"]

    return_dict = auth.ir_merge_permissions(ruleset)

    for rule in ruleset["permissions"]:
        assert rule in return_dict["permissions"]

    for rule in default_ruleset["permissions"]:
        assert rule in return_dict["permissions"]

    # Test 2
    assert {} == auth.ir_merge_permissions({})


def test_reduce_ruleset(pythapi):
    auth = pythapi.module_dict["auth"]

    ruleset = {
        "permissions": [
            "auth.self.get.permissions",
            "auth.self.get.permissions",
            "auth.self.session.*",
            "auth.self.session.create",
            "auth.self.token.create",
        ],
        "inherit": ["default", "default"],
    }

    shouldBe_ruleset = {
        "inherit": ["default"],
        "permissions": [
            "auth.self.get.permissions",
            "auth.self.session.*",
            "auth.self.token.create",
        ],
    }

    return_dict = auth.i_reduce_ruleset(ruleset)

    for section in ["permissions", "inherit"]:
        assert set(return_dict[section]) == set(shouldBe_ruleset[section])


def test_subset_intersector(pythapi):
    auth = pythapi.module_dict["auth"]

    ruleset = {
        "permissions": [
            "auth.self.session.*",
            "auth.self.token.*",
            "auth.user.get.self",
            "auth.self.get.permissions",
            "auth.user.edit.self.password",
            "auth.role.*",
        ],
        "inherit": ["default"],
    }

    subset = {
        "inherit": ["default"],
        "permissions": [
            "auth.self.get.permissions",
            "auth.self.session.*",
            "auth.self.token.create",
        ],
    }

    shouldBe_ruleset = {
        "permissions": [
            "auth.self.session.*",
            "auth.self.token.create",
            "auth.self.get.permissions",
        ],
        "inherit": ["default"],
    }

    intersected = auth.e_intersect_subset(ruleset, subset)

    for section in ["permissions", "inherit"]:
        assert set(intersected[section]) == set(shouldBe_ruleset[section])

    # Test 2: Negative Test
    subset = {
        "inherit": ["default", "not_permitted"],
        "permissions": [
            "auth.self.get.permissions",
            "auth.self.session.*",
            "auth.self.token.create",
            "auth.self.not_permitted.*",
            "auth.self.still_not_permitted",
        ],
    }

    intersected = auth.e_intersect_subset(ruleset, subset)

    for section in ["permissions", "inherit"]:
        assert set(intersected[section]) == set(shouldBe_ruleset[section])
