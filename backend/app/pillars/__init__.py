"""Detection pillars.

Each module exposes a pure `analyse(...) -> list[Signal]` function so pillars can
be unit tested in isolation and composed by `app.assembler` without ordering
dependencies.
"""
