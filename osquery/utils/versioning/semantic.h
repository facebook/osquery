/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/expected/expected.h>

#include <string>

namespace osquery {

class SemanticVersion {
 public:
  unsigned major = 0;
  unsigned minor = 0;
  unsigned patches = 0;
  unsigned build = 0;

 public:
  int compare(const SemanticVersion&);
  bool eq(const SemanticVersion&);

 public:
  bool operator==(const SemanticVersion& other) {
    return eq(other);
  }
  bool operator!=(const SemanticVersion& other) {
    return !eq(other);
  }
  bool operator>(const SemanticVersion& other) {
    return compare(other) > 0;
  }
  bool operator<(const SemanticVersion& other) {
    return compare(other) < 0;
  }
  bool operator>=(const SemanticVersion& other) {
    return compare(other) >= 0;
  }
  bool operator<=(const SemanticVersion& other) {
    return compare(other) <= 0;
  }

 public:
  static constexpr auto separator = '.';

 public:
  static Expected<SemanticVersion, ConversionError> tryFromString(
      const std::string& str);
};

template <typename ToType>
inline typename std::enable_if<std::is_same<ToType, SemanticVersion>::value,
                               Expected<ToType, ConversionError>>::type
tryTo(const std::string& str) {
  return SemanticVersion::tryFromString(str);
}

} // namespace osquery
