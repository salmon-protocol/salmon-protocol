#!/usr/bin/env python
# encoding: utf-8
#
# Copyright 2008 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Handles users for demo aggregator & proxy feed service"""

import sys
import os
import re

USERS = {"test@example.com": True,
"jpanzer@acm.org": True,
"chabotc@google.com": True,
"chabotc@google.com": True,
"kurrik@google.com": True,
"wiktorgworek@google.com": True,
"vli@google.com": True,
"cxs@google.com": True,
"jscudder@google.com": True,
"bradfitz@google.com": True,
"bobwyman@gmail.com": True,
"bslatkin@gmail.com": True,
"chabotc@gmail.com": True,
"dirk.balfanz@gmail.com": True,
}

def is_registered_user(u):
  # Check for trusted domains first:
  if re.match("[a-zA-Z\+_]+@google.com",u.email()):
    return True

  if u.email() in USERS:
    return True	

  return False