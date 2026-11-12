"""Explicit registry: detector modules are shipped code, never loaded from projects."""
from . import conan, cmake, python_env, lockfiles, images, sdk
DETECTORS = (conan, cmake, python_env, lockfiles, images, sdk)
