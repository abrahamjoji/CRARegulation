# Language-independent CRA collection

The analysis, policy, VEX, hosted API and gate operate on component evidence, not on a programming language. Select the appropriate evidence adapters for the project. Python and native code can be collected together in one configuration; Conan and CMake are optional.

The tool scans dependencies and selected artifacts. It is not a source-code vulnerability analyzer, and no adapter establishes complete discovery or exploitability.

| Project | Recommended evidence | Verified boundary |
| --- | --- | --- |
| Python | `pip inspect` from the actual environment; optional Syft directory/image inventory | Installed Python distributions, metadata and selected unconditional dependency edges |
| C | CMake File API, optional Conan graph, ELF artifacts, staged deployment/image inventory, component records | Same native adapters as C++; no C++ requirement |
| C++ | CMake File API, optional Conan graph, ELF artifacts, staged deployment/image inventory, component records | Configured targets and observed native metadata |
| Make/Meson/other native builds | Staged deployment directory/image, ELF artifacts and explicit component records | No build-system-specific graph inference; unidentified dependencies stay visible |
| Other languages | Selected directory or container inventory through pinned Syft | Whatever the installed Syft catalogers identify; not a promise of a dedicated adapter for every language |

## Platforms

Two questions decide whether a project is covered: where `cra` runs, and what the product is built for.

**Where `cra` runs.** Linux on x86-64 or ARM64, directly or in the collector image. `scripts/install_tools.sh` and the Dockerfiles pick the matching pinned Syft, Grype and cosign builds and refuse anything else with exit 30. x86-64 is fully tested. ARM64 is tested under QEMU emulation, with results identical to x86-64, but not yet on physical ARM64 hardware. Windows and macOS cannot run the CLI natively: it relies on Unix-only facilities for process limits and safe file access. On those hosts, run the collector image under Docker Desktop or WSL2.

**What the product is built for.**

| Product target | Coverage |
| --- | --- |
| Linux on any CPU (x86-64, ARM64, 32-bit ARM, RISC-V and others) | ELF inspection is architecture-independent: binaries cross-compiled for an embedded target can be inspected from an x86-64 build machine. A container image is scanned for one platform: from a multi-architecture index, Syft picks the machine's own platform. To cover another architecture, add an `[[images]]` entry pinned to that platform's manifest digest |
| Python distributions | Supported wherever `pip inspect` ran, because only its JSON is read. Capturing it on Windows or macOS and collecting on Linux is untested |
| Windows applications (PE executables, DLLs) | Not supported. Binaries are not inspected and no MSVC or vcpkg evidence is read. Syft may still identify packages from lockfiles in a directory scan |
| macOS applications (Mach-O) | Not supported |

## Python

Copy [the Python configuration](../examples/projects/python/cra.toml) into the customer's project root. After installing the customer's actual dependencies, run:

```bash
python -m pip inspect --local > pip-inspect.json
cra collect --config cra.toml
cra analyze --config cra.toml --kev /path/to/current-kev.json
cra gate --result .cra/analysis --mode build
```

`cra prepare` is optional and a successful no-op when no CMake build is configured. The collector reads JSON; it never executes Python project files, setup scripts, the target interpreter, pip or dependency installation.

Add `pip_inspect` to a `[[configurations]]` entry. `pip_inspect_scope` is `runtime` (default), `build_tool` or `test`. `pip_inspect_shipped` defaults to false: an inspected development environment is not automatically a deployed product. Set it to true only for an explicitly identified runtime deployment environment. That is a customer claim corroborated by installed distribution metadata, not independent attestation of deployment. A `python-env:<configuration>` artifact hash binds the result to the captured metadata; it does not hash the full environment.

The pip inspect schema must be version `1`. Python distribution names normalize case and `.`, `_`, `-` to the standard PyPI name form. Duplicate normalized names, unsupported schema versions, malformed or missing metadata and missing unconditional dependencies are reported rather than ignored.

Limitations: markers/extras are retained without evaluation, version constraints are not checked, editable/direct installs may be forks, and Python extension modules can have native dependencies that require artifact or filesystem evidence. Use the customer's own `pip check` separately for environment consistency. The report preserves these limitations.

## C and C++

Copy [the native configuration](../examples/projects/native/cra.toml) and adjust the build directory and artifact names:

```bash
cra prepare --config cra.toml
cmake -S . -B build
cmake --build build
cra collect --config cra.toml
cra analyze --config cra.toml --kev /path/to/current-kev.json
cra gate --result .cra/analysis
```

CMake projects using `LANGUAGES C`, `LANGUAGES CXX` or both use the same collector. Conan is optional; when present, capture its actual resolved graph and add `conan_graph`. Without package identity evidence, link flags and ELF library names do not establish versions. A compiler-produced ELF hash alone cannot make an empty dependency inventory complete. Supply package evidence or component records.

For non-CMake projects, omit `cra prepare`. Build normally and collect staged files, exported images, selected ELF files and component records. Static/vendored/proprietary libraries may still require explicit records.

## Directory scanning

Use [the generic directory configuration](../examples/projects/directory/cra.toml):

```toml
[[directories]]
id = "deployment-tree"
path = "deploy"
role = "final"
required = true
```

Roles: `source` means declarations/detection evidence with shipping unknown; `final` identifies a selected deployment tree; `build-stage` records build-environment packages. Source lockfiles do not prove that their packages ship.

Directories must fall inside `scope.roots`. The collector creates a temporary bounded snapshot and scans it with Syft. It retains hashes and scanner JSON, not copies of source files. `.git` and configured CRA output folders are excluded. Symlinks and special files are refused, and limits are 100000 files and 1 GiB per directory. Scan a narrow staged tree instead of a whole workstation. A Python venv commonly contains symlinks: use `pip inspect` for that environment instead of copying the venv into a directory scan.

Snapshot identity hashes the sorted, relative file manifest. The scanner runs from an isolated temporary working directory so repository `.syft.yaml` files cannot silently change its behavior. Missing directories, scanner failures, unverified tool/schema versions and zero detected packages are incomplete, not clean.

## Docker and CI

The CLI and collector container use the same adapters. Python metadata-only collection requires neither a Conan installation nor a C/C++ compiler in the collector. Build tools stay in the customer build job; the container reads the resulting evidence. Directory scanning uses bundled Syft without a Docker daemon socket. All configured input paths must be visible in the container mount.

The shared action is a thin prepare/collect wrapper and has no language restriction. The build step in [the existing workflow example](../examples/github-actions/cra.yml) is an example native customer build; replace it with the customer's own Python or other build, then invoke the same collect/analyze/gate commands.

## References

- [pip inspect JSON v1](https://pip.pypa.io/en/stable/reference/inspect-report/)
- [Syft file selection and directory scanning](https://oss.anchore.com/docs/guides/sbom/file-selection/)
