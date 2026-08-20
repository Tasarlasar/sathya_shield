"""Trained model inference.

Everything in this package emits signals with `deterministic=False`, which is
what confines model output to AMBER under the section 14.2 decision policy. That
is not a detail to be optimised away later: it is the property that stops a
probabilistic classifier from taking over a frightened user's screen.

Models load lazily and degrade to silence if their artifact is missing, so the
service runs correctly on a checkout that has never executed `ml/train_*.py`.
"""
