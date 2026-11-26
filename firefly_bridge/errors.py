"""Typed boundary between a known durable pre-write rejection and ambiguity."""


class PreSendRejected(ValueError):
    """Raised only after a no-attempt rejection has been durably committed.

    Never catch arbitrary StoreError/transport failures as this exception: once
    claim or write is ambiguous, the target must retain its unknown lease.
    """
