# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function


class DebugUtil:
    debug = False

    @classmethod
    def log(cls, obj: object, output: str) -> None:
        if DebugUtil.debug:
            print(f'{type(obj).__name__}: {output}')
