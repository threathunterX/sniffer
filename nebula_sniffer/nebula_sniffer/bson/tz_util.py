"""Timezone related utilities for BSON."""

from datetime import (timedelta,
                      tzinfo)

ZERO = timedelta(0)


class FixedOffset(tzinfo):
    """Fixed offset timezone, in minutes east from UTC.

    Implementation based from the Python `standard library documentation
    <http://docs.python.org/library/datetime.html#tzinfo-objects>`_.
    Defining __getinitargs__ enables pickling / copying.
    """

    def __init__(self, offset, name):
        if isinstance(offset, timedelta):
            self.__offset = offset
        else:
            self.__offset = timedelta(minutes=offset)
        self.__name = name

    def __getinitargs__(self):
        return self.__offset, self.__name

    def utcoffset(self, dt):
        return self.__offset

    def tzname(self, dt):
        return self.__name

    def dst(self, dt):
        return ZERO


utc = FixedOffset(0, "UTC")
"""Fixed offset timezone representing UTC."""
