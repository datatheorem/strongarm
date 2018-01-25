# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function


class DebugUtil(object):
    debug = False

    @classmethod
    def log(cls, obj, output):  # type: ignore
        if DebugUtil.debug:
            print('{}: {}'.format(type(obj).__name__, output))
