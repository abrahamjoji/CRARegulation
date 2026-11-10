#include <fmt/core.h>
#include <nlohmann/json.hpp>
#include <zlib.h>
#ifdef WITH_LZ4
#include <lz4.h>
#endif
#include <cstring>
#include "tinycrc.h"

int main() {
  const char *message = "reference-gateway";
  const auto *bytes = reinterpret_cast<const unsigned char *>(message);
  nlohmann::json report;
  report["zlib"] = zlibVersion();
  report["crc"] = crc32(0L, bytes, static_cast<uInt>(std::strlen(message)));
  unsigned char packed[128];
  uLongf packed_size = sizeof(packed);
  report["compressed"] = compress(packed, &packed_size, bytes, std::strlen(message)) == Z_OK ? packed_size : 0;
  report["tinycrc"] = tinycrc32(bytes, std::strlen(message));
  report["tinycrc_version"] = tinycrc_version();
#ifdef WITH_LZ4
  report["lz4"] = LZ4_versionString();
#endif
  fmt::print("{}\n", report.dump());
  return 0;
}
