"""Shared slowapi rate limiter.

Lives in its own module so both `app.main` (to register app state + the
RateLimitExceeded handler) and the routers (to apply per-route limits) can
import the same Limiter instance without a circular import through main.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

# key_func=get_remote_address -> limits are tracked per client IP.
limiter = Limiter(key_func=get_remote_address)
