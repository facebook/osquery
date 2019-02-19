# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

load(
    "//tools/build_defs/oss/osquery:cxx.bzl",
    _osquery_cxx_library = "osquery_cxx_library",
    _osquery_prebuilt_cxx_library = "osquery_prebuilt_cxx_library",
    _osquery_prebuilt_cxx_library_group = "osquery_prebuilt_cxx_library_group",
)
load(
    "//tools/build_defs/oss/osquery:defaults.bzl",
    _OSQUERY_CELL_NAME = "OSQUERY_CELL_NAME",
    _OSQUERY_THIRD_PARTY_PATH = "OSQUERY_THIRD_PARTY_PATH",
)
load(
    "//tools/build_defs/oss/osquery:native.bzl",
    _osquery_genrule = "osquery_genrule",
    _osquery_get_current_platform = "osquery_get_current_platform",
)
load(
    "//tools/build_defs/oss/osquery:native_functions.bzl",
    _osquery_read_config = "osquery_read_config",
)
load(
    "//tools/build_defs/oss/osquery:platforms.bzl",
    _LINUX = "LINUX",
    _MACOSX = "MACOSX",
    _WINDOWS = "WINDOWS",
)
load(
    "//tools/build_defs/oss/osquery:python.bzl",
    _osquery_prebuilt_python_library = "osquery_prebuilt_python_library",
    _osquery_python_library = "osquery_python_library",
)
load(
    "//tools/build_defs/oss/osquery:third_party_archive.bzl",
    _osquery_tp_prebuilt_cxx_archive = "osquery_tp_prebuilt_cxx_archive",
    _osquery_tp_prebuilt_python_archive = "osquery_tp_prebuilt_python_archive",
)

_PLATFORM_MAP = {
    "linux-x86_64": [
        _LINUX,
    ],
    "macos-x86_64": [
        _MACOSX,
    ],
    "windows-x86_64": [
        _WINDOWS,
    ],
}

_CXX_ARCHIVE_TYPE = "tar.gz"

def _static_lib_file_target_name(
        name,
        version,
        platform,
        static_lib):
    return "{}_{}_{}_{}_static_lib_file".format(
        name,
        version,
        platform,
        static_lib,
    )

def _static_lib_file(
        name,
        version,
        platform,
        archive_target,
        static_lib):
    target_name = _static_lib_file_target_name(
        name,
        version,
        platform,
        static_lib,
    )

    if platform == "windows-x86_64":
        static_lib = static_lib.replace("/", "\\")

    _osquery_genrule(
        name = target_name,
        out = static_lib,
        cmd = (
            "mkdir -p \$(dirname $OUT) " +
            "&& cp $(location :{})/{}/{}/{} $OUT"
        ).format(
            archive_target,
            name,
            version,
            static_lib,
        ),
        cmd_exe = (
            "mkdir %OUT%\.. " +
            "&& mklink %OUT% $(location :{})\{}\{}\{}"
        ).format(
            archive_target,
            name,
            version,
            static_lib,
        ),
    )

    return target_name

def _static_lib(
        name,
        version,
        platform,
        archive_target,
        static_lib,
        linker_flags,
        deps):
    static_lib_file_target = _static_lib_file(
        name,
        version,
        platform,
        archive_target,
        static_lib,
    )

    target_name = "{}_{}_{}_{}_static_lib".format(
        name,
        version,
        platform,
        static_lib,
    )

    _osquery_prebuilt_cxx_library(
        name = target_name,
        exported_linker_flags = linker_flags,
        static_lib = ":{}".format(static_lib_file_target),
        exported_deps = deps,
    )

    return target_name

def _static_lib_group(
        name,
        version,
        platform,
        archive_target,
        static_libs,
        linker_flags,
        deps):
    target_name = "{}_{}_{}_static_lib_group".format(
        name,
        version,
        platform,
    )

    static_lib_targets = []
    for static_lib in static_libs:
        static_lib_targets.append(
            _static_lib_file(
                name,
                version,
                platform,
                archive_target,
                static_lib,
            ),
        )
    _osquery_prebuilt_cxx_library_group(
        name = target_name,
        static_libs = [
            ":{}".format(target)
            for target in static_lib_targets
        ],
        static_link = [
            "-Wl,--start-group",
        ] + [
            "$(lib {})".format(i)
            for i in range(0, len(static_lib_targets))
        ] + [
            "-Wl,--end-group",
        ] + linker_flags,
        exported_deps = deps,
    )

    return target_name

def _header_dir(
        name,
        version,
        platform,
        archive_target):
    target_name = "{}_{}_{}_header_dir".format(
        name,
        version,
        platform,
    )

    _osquery_genrule(
        name = target_name,
        out = "include",
        cmd = (
            "ln -s -f $(location :{})/{}/{}/include $OUT"
        ).format(
            archive_target,
            name,
            version,
        ),
        cmd_exe = (
            "mklink /D %OUT% $(location :{})\{}\{}\include"
        ).format(
            archive_target,
            name,
            version,
        ),
    )

    return target_name

def _prebuilt_library(
        name,
        version,
        platform,
        header_dirs_targets,
        static_lib_targets):
    target_name = "{}_{}_{}_prebuilt_library".format(
        name,
        version,
        platform,
    )

    _osquery_prebuilt_cxx_library(
        name = target_name,
        header_namespace = "",
        header_dirs = [
            ":{}".format(target)
            for target in header_dirs_targets
        ],
        header_only = True,
        exported_deps = [
            ":{}".format(target)
            for target in static_lib_targets
        ],
    )

    return target_name

def osquery_tp_prebuilt_cxx_library(
        name,
        version,
        build,
        platforms,
        sha256sums,
        static_libs = None,
        platform_static_libs = None,
        linker_flags = None,
        deps = None):
    platform_prebuilt_library_targets = []
    exported_platform_preprocessor_flags = []
    exported_platform_linker_flags = []
    for platform in platforms:
        archive_target = _osquery_tp_prebuilt_cxx_archive(
            name = name,
            archive_type = _CXX_ARCHIVE_TYPE,
            platform = platform,
            sha256sum = sha256sums[platform],
            version = version,
            build = build,
        )

        header_dir_targets = [
            _header_dir(
                name,
                version,
                platform,
                archive_target,
            ),
        ]

        effective_static_libs = []
        if static_libs:
            effective_static_libs += static_libs
        if platform_static_libs and platform in platform_static_libs:
            effective_static_libs += platform_static_libs[platform]

        # Linux supports --start-group linker flag so use a library_group
        # This fixes dependency problems within pre-built libraries
        static_lib_targets = []
        if platform.startswith("linux"):
            static_lib_targets.append(
                _static_lib_group(
                    name,
                    version,
                    platform,
                    archive_target,
                    effective_static_libs,
                    linker_flags or [],
                    deps or [],
                ),
            )
        elif effective_static_libs:
            for static_lib in effective_static_libs:
                static_lib_targets.append(
                    _static_lib(
                        name,
                        version,
                        platform,
                        archive_target,
                        static_lib,
                        linker_flags or [],
                        deps or [],
                    ),
                )

        prebuilt_library_target = _prebuilt_library(
            name,
            version,
            platform,
            header_dir_targets,
            static_lib_targets,
        )

        for effective_platform in _PLATFORM_MAP[platform]:
            platform_prebuilt_library_targets.append((
                effective_platform,
                [":{}".format(prebuilt_library_target)],
            ))

        # Prebuilt libs are ignored in xcode project
        # Following code adds support via linker flags and pp flags
        if _osquery_read_config("osquery", "xcode", False):
            for effective_platform in _PLATFORM_MAP[platform]:
                target_name = header_dir_targets[0]
                xcode_headers_search_path = (effective_platform, ["-I$(location :{})".format(target_name)])
                xcode_linker_flags = linker_flags or []
                exported_platform_preprocessor_flags.append(xcode_headers_search_path)
                for static_lib in effective_static_libs:
                    xcode_linker_flags.append(
                        "$(location :{})".format(
                            _static_lib_file_target_name(
                                name,
                                version,
                                platform,
                                static_lib,
                            ),
                        ),
                    )
                exported_platform_linker_flags.append((effective_platform, xcode_linker_flags))

    _osquery_cxx_library(
        name = name,
        external = True,
        platform_deps = platform_prebuilt_library_targets,
        visibility = ["PUBLIC"],
        exported_platform_preprocessor_flags = exported_platform_preprocessor_flags,
        exported_platform_linker_flags = exported_platform_linker_flags,
    )

def osquery_tp_prebuilt_python_library(
        name,
        platforms,
        filenames,
        sha1sums,
        deps = None):
    platform = _osquery_get_current_platform()

    # If specifc platform isn't available fallback to none
    if platform not in platforms:
        platform = "none"

    if platform not in platforms:
        # If platform or none not available then library isn't available for
        # this platform. Create an empty python_library.
        _osquery_python_library(
            name = name,
            visibility = ["PUBLIC"],
            deps = deps or [],
        )
    else:
        # Otherwise plaform is available, create archive rule and make that the
        # binary_src for the prebuilt library.
        filename = filenames[platform]
        sha1sum = sha1sums[platform]

        file_target = _osquery_tp_prebuilt_python_archive(
            name,
            filename,
            platform,
            sha1sum,
        )

        binary_src = ":{}".format(file_target)

        _osquery_prebuilt_python_library(
            name = name,
            binary_src = binary_src,
            visibility = ["PUBLIC"],
            deps = deps or [],
        )

def osquery_tp_target(name, lib = None):
    return "{}{}/{}:{}".format(
        _OSQUERY_CELL_NAME,
        _OSQUERY_THIRD_PARTY_PATH,
        name,
        lib or name,
    )
