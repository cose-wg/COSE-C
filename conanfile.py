import os
from conans import ConanFile, CMake, tools


class CoseCConan(ConanFile):
    name = "cose-c"
    version = "20200225"
    license = "BSD"
    url = "https://github.com/cose-wg/COSE-C"
    description = """;"""
    topics = ("COSE")
    settings = "os", "compiler", "build_type", "arch"
    options = {
        "shared": [True, False],
        "use_embedtls": [True, False]
    }
    default_options = {
        "shared": False,
        "use_embedtls": False
    }
    
    generators = "cmake", "cmake_find_package"

    _cmake = None

    @property
    def _source_subfolder(self):
        return "source_subfolder"

    @property
    def _build_subfolder(self):
        return "build_subfolder"

    def source(self):
        self.run(
            "git clone -b build--improve-cmake https://github.com/gocarlos/COSE-C.git")

        # self.run(
            # "git clone https://github.com/cose-wg/COSE-C.git")

        os.rename("COSE-C", self._source_subfolder)

    def requirements(self):
        self.requires("cn-cbor/20200227@gocarlos/testing")

        if self.options.use_embedtls:
            self.requires("mbedtls/2.16.3-gpl")
        else:
            self.requires("openssl/1.1.1d")

    def configure(self):
        del self.settings.compiler.libcxx
        del self.settings.compiler.cppstd

    def _configure_cmake(self):
        if not self._cmake:
            self._cmake = CMake(self)
        self._cmake.definitions["build_tests"] = False
        self._cmake.definitions["build_docs"] = False
        self._cmake.definitions["use_embedtls"] = self.options.use_embedtls
        self._cmake.definitions["coveralls"] = False
        self._cmake.definitions["COSE_C_USE_PROJECT_ADD"] = False
        # self._cmake.configure(source_folder="COSE-C")
        self._cmake.configure(
            source_folder=self._source_subfolder, build_folder=self._build_subfolder)

        return self._cmake

    def build(self):
        cmake = self._configure_cmake()
        cmake.build()

    def package(self):
        cmake = self._configure_cmake()
        cmake.install()

    def package_info(self):
        self.cpp_info.libs = ["cose-c"]
        self.cpp_info.name = "cose-c"
