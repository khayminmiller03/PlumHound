import logging
import time
from typing import Callable, TypeVar, ParamSpec, Any

from neo4j.exceptions import ServiceUnavailable, SessionExpired, TransientError

RETRY = (ServiceUnavailable, SessionExpired, TransientError)

loggy = logging.getLogger("PlumHound")

P = ParamSpec("P")
R = TypeVar("R")

def retry_on_tran(max_attempts : int = 3, delay : int = 1) -> Callable[[Callable[P, R]], Callable[P, R]]:
    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except RETRY as e:
                    if attempt == max_attempts:
                        raise
                    de = delay * (2 ** (attempt - 1))
                    loggy.warning(f"Transient error on attempt {attempt}, retrying in {de}s: {e}")
                    time.sleep(de)
            # myPy flag      
            raise RuntimeError("unreachable: retry loop exited without returning or raising")

        return wrapper

    return decorator
