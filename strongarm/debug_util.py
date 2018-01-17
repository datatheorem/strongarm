# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

from typing import Any, Text

class DebugUtil(object):
    debug = False

    @classmethod
    def log(cls, obj, output):
        # type: (Any, Any, Text) -> None
        if DebugUtil.debug:
            print('{}: {}'.format(type(obj).__name__, output))
