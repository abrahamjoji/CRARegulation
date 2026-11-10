#!/usr/bin/env bash
# Build the reference customer project with real Conan and CMake, in the order CI would use.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
export PATH="$repo/.venv/bin:$PATH"
export CONAN_HOME="${CONAN_HOME:-$repo/.cra/conan-home}"
cra() { PYTHONPATH="$repo/src" python3 -m cra.cli_main "$@"; }
mkdir -p "$here/out"
[ -f "$CONAN_HOME/profiles/default" ] || conan profile detect --force >/dev/null

# prepare must run before CMake configures.
cra prepare --config "$here/cra.toml"

cd "$here/app"
build_one() {
  local name="$1" type="$2" lz4="$3"
  conan install . -pr:h "profiles/$name" -pr:b default --build=missing -of "build-$name" -f json --out-file "$here/out/$name.graph.json" >"$here/out/$name.log" 2>&1
  local tree="build-$name/build/$type"
  cmake -S . -B "$tree" -G Ninja -DCMAKE_TOOLCHAIN_FILE="$PWD/$tree/generators/conan_toolchain.cmake" -DCMAKE_BUILD_TYPE="$type" -DWITH_LZ4="$lz4" >>"$here/out/$name.log" 2>&1
  cmake --build "$tree" >>"$here/out/$name.log" 2>&1
  "./$tree/gateway"
}
build_one release-static Release OFF
build_one debug-shared-lz4 Debug ON
python3 "$here/tools/build_fixture_images.py" --binary "$here/app/build-release-static/build/Release/gateway" --out "$here/out"
