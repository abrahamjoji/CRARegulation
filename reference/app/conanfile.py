"""Reference customer recipe. Fictional product; dependencies are real Conan Center packages."""
from conan import ConanFile
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout


class ReferenceGateway(ConanFile):
    name = "reference-gateway"
    version = "1.0.0"
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared_deps": [True, False], "with_lz4": [True, False]}
    default_options = {"shared_deps": False, "with_lz4": False}
    # Exact versions on purpose: the expected inventories assert them.
    requires = ("zlib/1.2.13", "fmt/12.1.0", "nlohmann_json/3.11.3")
    tool_requires = ("ninja/1.13.1",)
    test_requires = ("doctest/2.5.2",)

    def requirements(self):
        if self.options.with_lz4:
            self.requires("lz4/1.10.0")

    def configure(self):
        self.options["zlib/*"].shared = bool(self.options.shared_deps)
        self.options["fmt/*"].shared = bool(self.options.shared_deps)

    def layout(self):
        cmake_layout(self)

    def generate(self):
        CMakeDeps(self).generate()
        toolchain = CMakeToolchain(self, generator="Ninja")
        toolchain.cache_variables["WITH_LZ4"] = bool(self.options.with_lz4)
        toolchain.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
