// Copyright 2004-present Facebook. All Rights Reserved.

#ifndef OSQUERY_FILESYSTEM_H
#define OSQUERY_FILESYSTEM_H

#include <map>
#include <string>
#include <vector>

#include <boost/property_tree/ptree.hpp>

#include "osquery/status.h"

namespace osquery {
namespace fs {

// readFile accepts a const reference to an std::string indicating the path of
// the file that you'd like to read and a non-const reference to an std::string
// which will be populated with the contents of the file (if all operations are
// successful). An osquery::Status is returned indicating the success or
// failure of the operation.
osquery::Status readFile(const std::string &path, std::string &content);

// listFilesInDirectory accepts a const reference to an std::string indicating
// the path of the directory that you'd like to list and a non-const reference
// to an std::vector<std::string> which will be populated with the contents of
// the directory (if all operations are successful). An osquery::Status is
// returned indicating the success or failure of the operation. Note that the
// directory listing is not recursive.
osquery::Status listFilesInDirectory(const std::string &path,
                                     std::vector<std::string> &results);

#ifdef __APPLE__
osquery::Status parsePlist(const std::string &path,
                           boost::property_tree::ptree &tree);
osquery::Status parsePlistContent(const std::string &fileContent,
                                  boost::property_tree::ptree &tree);
#endif
}
}

#endif /* OSQUERY_FILESYSTEM_H */
