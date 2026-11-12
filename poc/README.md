# Proofs of concept

This folder holds demonstrations and example product builds, not the scanner runtime.

- [legacy/](legacy/README.md): the original DEMO-200 report pipeline, its scripts, fictional product records, sample inputs and checked-in example reports.
- [reference/](reference/README.md): the representative Conan/CMake application, vendor records and image fixtures used to exercise the platform.

Reusable customer-facing configurations belong in `../examples/`. Regression tests belong in `../tests/`, not beside demo applications. Product runtime code and blank templates used by the CLI belong only in `../src/cra/`.
