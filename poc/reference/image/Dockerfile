# Multi-stage reference build. Built and run manually (docs/TEST_RESULTS.md); routine tests use
# poc/reference/tools/build_fixture_images.py, which writes OCI archives of the same
# structure without a Docker daemon. Pin both images by digest before real use.
FROM debian:bookworm-slim AS builder
# make: Conan builds missing dependencies with CMake's default Makefile generator.
RUN apt-get update && apt-get install -y --no-install-recommends g++ make cmake ninja-build python3-pip
RUN pip3 install --break-system-packages conan==2.34.0
COPY app /src
WORKDIR /src
# The profile names the reference host's GCC 16; bookworm ships GCC 12, so record the compiler actually used.
RUN conan profile detect \
 && conan install . -pr:h profiles/release-static -s:h compiler.version=12 -pr:b default --build=missing -of build -f json --out-file /graph.json \
 && cmake -S . -B build/build/Release -G Ninja -DCMAKE_TOOLCHAIN_FILE=build/build/Release/generators/conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build/build/Release

FROM debian:bookworm-slim AS final
COPY --from=builder /src/build/build/Release/gateway /opt/gateway/gateway
ENTRYPOINT ["/opt/gateway/gateway"]
