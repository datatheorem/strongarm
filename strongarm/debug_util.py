class DebugUtil(object):
    debug = False

    @classmethod
    def log(cls, obj, output):
        if DebugUtil.debug:
            print('{}: {}'.format(type(obj).__name__, output))
