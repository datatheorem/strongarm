class DebugUtil:
    debug = False

    @classmethod
    def log(cls, obj, output):  # type: ignore
        if DebugUtil.debug:
            print('{}: {}'.format(type(obj).__name__, output))
