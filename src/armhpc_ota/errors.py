# SPDX-License-Identifier: GPL-3.0-only
class OTAError(RuntimeError):
    def __init__(self, code, message, **details):
        super().__init__(message)
        self.code, self.details = code, details


def require(condition, code, message, **details):
    if not condition:
        raise OTAError(code, message, **details)
