class PwnlibException(Exception):
    reason: Exception | None
    exit_code: int | None
    message: str