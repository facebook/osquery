/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/utils/system/env.h>
#include <osquery/utils/conversions/windows/strings.h>

#include <string>
#include <vector>

#include <boost/optional.hpp>

#include <windows.h>

namespace osquery {

const auto kInitialBufferSize = 1024;

bool setEnvVar(const std::string& name, const std::string& value) {
  return (::SetEnvironmentVariableA(name.c_str(), value.c_str()) == TRUE);
}

bool unsetEnvVar(const std::string& name) {
  return (::SetEnvironmentVariableA(name.c_str(), nullptr) == TRUE);
}

boost::optional<std::string> getEnvVar(const std::string& name) {
  std::vector<char> buf;
  buf.assign(kInitialBufferSize, '\0');

  auto value_len =
      ::GetEnvironmentVariableA(name.c_str(), buf.data(), kInitialBufferSize);
  if (value_len == 0) {
    return boost::none;
  }

  // It is always possible that between the first GetEnvironmentVariableA call
  // and this one, a change was made to our target environment variable that
  // altered the size. Currently, we ignore this scenario and fail if the
  // returned size is greater than what we expect.
  if (value_len > kInitialBufferSize) {
    buf.assign(value_len, '\0');
    value_len = ::GetEnvironmentVariableA(name.c_str(), buf.data(), value_len);
    if (value_len == 0 || value_len > buf.size()) {
      // The size returned is greater than the size we expected. Currently, we
      // will not deal with this scenario and just return as if an error has
      // occurred.
      return boost::none;
    }
  }

  return std::string(buf.data(), value_len);
}

boost::optional<std::string> expandEnvString(const std::string& input) {
  std::vector<char> buf;
  buf.assign(kInitialBufferSize, '\0');

  // ExpandEnvironmentStrings doesn't support inputs larger than 32k.
  if (input.size() > 32768) {
    return boost::none;
  }

  auto len = ::ExpandEnvironmentStrings(input.c_str(), buf.data(), kInitialBufferSize);
  if (len == 0) {
    return boost::none;
  }

  if (len > kInitialBufferSize) {
    buf.assign(len, '\0');
    len = ::ExpandEnvironmentStrings(input.c_str(), buf.data(), len);
  }

  if (len == 0) {
    return boost::none;
  }

  return std::string(buf.data(), len);
}

boost::optional<std::vector<std::string>> splitArgs(const std::string& args) {
  int argc;

  auto argv = CommandLineToArgvW(stringToWstring(args), &argc);
  if (argv == nullptr) {
    return boost::none;
  }

  std::vector<std::string> argvec;
  for (int i = 0; i < argc; ++i) {
    argvec.push_back(wstringToString(std::wstring(argv[i])));
  }

  LocalFree(argv);

  return argvec;
}

} // namespace osquery
