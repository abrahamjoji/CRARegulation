# Multi-stage reference build. Not built in routine tests: use
# reference/tools/build_fixture_images.py, which writes OCI archives of the same
# structure without a Docker daemon. Pin both images by digest before real use.
FROM debian:bookworm-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends g++ cmake ninja-build python3-pip
RUN pip3 install --break-system-packages conan==2.34.0
COPY app /src
WORKDIR /src
RUN conan profile detect \
 && conan install . -pr:h profiles/release-static -pr:b default --build=missing -of build -f json --out-file /graph.json \
 && cmake -S . -B build/build/Release -G Ninja -DCMAKE_TOOLCHAIN_FILE=build/build/Release/generators/conan_toolchain.cmake \
 && cmake --build build/build/Release

FROM debian:bookworm-slim AS final
COPY --from=builder /src/build/build/Release/gateway /opt/gateway/gateway
ENTRYPOINT ["/opt/gateway/gateway"]
