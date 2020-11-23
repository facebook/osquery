/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/versioning/semantic.h>

#include <boost/io/detail/quoted_manip.hpp>

#include <iostream>

namespace osquery {

using boost::io::quoted;

Expected<SemanticVersion, ConversionError> SemanticVersion::tryFromString(
    const std::string& str) {
  auto version = SemanticVersion{};

  auto const major_number_pos = str.find(SemanticVersion::separator);
  {
    if (major_number_pos == std::string::npos) {
      return createError(ConversionError::InvalidArgument)
             << "invalid format: expected 2 separators, found 0 "
             << quoted(str);
    }
    auto major_exp = tryTo<unsigned>(str.substr(0, major_number_pos));
    if (major_exp.isError()) {
      return createError(ConversionError::InvalidArgument,
                         major_exp.takeError())
             << "Invalid major version number, expected unsigned integer, "
                "found "
             << quoted(str);
    }
    version.major = major_exp.take();
  }

  auto const minor_number_pos =
      str.find(SemanticVersion::separator, major_number_pos + 1);
  {
    if (minor_number_pos == std::string::npos) {
      return createError(ConversionError::InvalidArgument)
             << " there are must be 2 separators, found 1 " << quoted(str);
    }
    auto minor_exp = tryTo<unsigned>(
        str.substr(major_number_pos + 1, minor_number_pos - major_number_pos));
    if (minor_exp.isError()) {
      return createError(ConversionError::InvalidArgument,
                         minor_exp.takeError())
             << "Invalid minor version number, expected unsigned integer, "
                "found: "
             << quoted(str);
    }
    version.minor = minor_exp.take();
  }

  auto const patch_number_pos =
      str.find_first_not_of("0123456789", minor_number_pos + 1);
  {
    auto patches_exp = tryTo<unsigned>(
        str.substr(minor_number_pos + 1, patch_number_pos - minor_number_pos));
    if (patches_exp.isError()) {
      return createError(ConversionError::InvalidArgument)
             << "Invalid patches number, expected unsigned integer, found: "
             << quoted(str);
    }
    version.patches = patches_exp.take();
  }

  // patch_number_pos represents the trailing separator, if it is
  // npos, then there is no build.
  if (patch_number_pos == std::string::npos) {
    return version;
  }

  auto const build_number_pos =
      str.find_first_not_of("0123456789", patch_number_pos + 1);
  {
    auto build_exp = tryTo<unsigned>(
        str.substr(patch_number_pos + 1, build_number_pos - patch_number_pos));
    // build is optional. If we can't parse it, ignore this.
    if (!build_exp.isError()) {
      version.build = build_exp.take();
    }
  }

  return version;
}

int SemanticVersion::compare(const SemanticVersion& other) {
  if (eq(other)) {
    return 0;
  }

  if (major > other.major) {
    return 1;
  }

  if (major < other.major) {
    return -1;
  }

  if (minor > other.minor) {
    return 1;
  }

  if (minor < other.minor) {
    return -1;
  }

  if (patches > other.patches) {
    return 1;
  }

  if (patches < other.patches) {
    return -1;
  }

  if (build > other.build) {
    return 1;
  }

  if (build < other.build) {
    return -1;
  }

  // May as well return equal...
  return 0;
}

bool SemanticVersion::eq(const SemanticVersion& other) {
  return major == other.major && minor == other.minor &&
         patches == other.patches && build == other.build;
}

} // namespace osquery
