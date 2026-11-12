# Reference product proof of concept

This is a fictional customer project used to validate build-aware scanning. It is not required to install or run the scanner on another product.

From the repository root, after installing the pinned tools and Conan/CMake:

```bash
poc/reference/build_reference.sh
cra collect --config poc/reference/cra.toml
cra analyze --config poc/reference/cra.toml
cra gate --result poc/reference/out/cra/analysis
```

The build script locates the repository root itself. Tool binaries remain in the root `.tools/`; reference build products and scanner results stay under this folder and are ignored by Git. Regenerate native build trees after this move: cached CMake/Conan files may contain absolute paths from the previous location.

Expected inventory lives in `expected/`; deterministic scanner captures live in `../../tests/fixtures/reference/`. Real-tool integration tests are under `../../tests/integration/`.
