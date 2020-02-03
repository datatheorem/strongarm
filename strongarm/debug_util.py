class DebugUtil:
    debug = False

    @classmethod
    def log(cls, obj: object, output: str) -> None:
        if DebugUtil.debug:
            print(f"{type(obj).__name__}: {output}")
