"""Exceptions raised by the BSON package."""


class BSONError(Exception):
    """Base class for all BSON exceptions.
    """


class InvalidBSON(BSONError):
    """Raised when trying to create a BSON object from invalid data.
    """


class InvalidStringData(BSONError):
    """Raised when trying to encode a string containing non-UTF8 data.
    """


class InvalidDocument(BSONError):
    """Raised when trying to create a BSON object from an invalid document.
    """


class InvalidId(BSONError):
    """Raised when trying to create an ObjectId from invalid data.
    """
