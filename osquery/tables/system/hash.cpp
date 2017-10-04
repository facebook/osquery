/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <iomanip>
#include <sstream>
#include <vector>
#include <queue>

#include <openssl/md5.h>
#include <openssl/sha.h>

#include <boost/filesystem.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/tables/system/hash.h"

namespace osquery {

#define HASH_CHUNK_SIZE 4096

Hash::~Hash() {
  if (ctx_ != nullptr) {
    free(ctx_);
  }
}

Hash::Hash(HashType algorithm) : algorithm_(algorithm) {
  if (algorithm_ == HASH_TYPE_MD5) {
    length_ = MD5_DIGEST_LENGTH;
    ctx_ = (MD5_CTX*)malloc(sizeof(MD5_CTX));
    MD5_Init((MD5_CTX*)ctx_);
  } else if (algorithm_ == HASH_TYPE_SHA1) {
    length_ = SHA_DIGEST_LENGTH;
    ctx_ = (SHA_CTX*)malloc(sizeof(SHA_CTX));
    SHA1_Init((SHA_CTX*)ctx_);
  } else if (algorithm_ == HASH_TYPE_SHA256) {
    length_ = SHA256_DIGEST_LENGTH;
    ctx_ = (SHA256_CTX*)malloc(sizeof(SHA256_CTX));
    SHA256_Init((SHA256_CTX*)ctx_);
  } else {
    throw std::domain_error("Unknown hash function");
  }
}

void Hash::update(const void* buffer, size_t size) {
  if (algorithm_ == HASH_TYPE_MD5) {
    MD5_Update((MD5_CTX*)ctx_, buffer, size);
  } else if (algorithm_ == HASH_TYPE_SHA1) {
    SHA1_Update((SHA_CTX*)ctx_, buffer, size);
  } else if (algorithm_ == HASH_TYPE_SHA256) {
    SHA256_Update((SHA256_CTX*)ctx_, buffer, size);
  }
}

std::string Hash::digest() {
  std::vector<unsigned char> hash;
  hash.assign(length_, '\0');

  if (algorithm_ == HASH_TYPE_MD5) {
    MD5_Final(hash.data(), (MD5_CTX*)ctx_);
  } else if (algorithm_ == HASH_TYPE_SHA1) {
    SHA1_Final(hash.data(), (SHA_CTX*)ctx_);
  } else if (algorithm_ == HASH_TYPE_SHA256) {
    SHA256_Final(hash.data(), (SHA256_CTX*)ctx_);
  }

  // The hash value is only relevant as a hex digest.
  std::stringstream digest;
  for (size_t i = 0; i < length_; i++) {
    digest << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
  }

  return digest.str();
}

std::string hashFromBuffer(HashType hash_type,
                           const void* buffer,
                           size_t size) {
  Hash hash(hash_type);
  hash.update(buffer, size);
  return hash.digest();
}

MultiHashes hashMultiFromFile(int mask, const std::string& path) {
  std::map<HashType, std::shared_ptr<Hash>> hashes = {
      {HASH_TYPE_MD5, std::make_shared<Hash>(HASH_TYPE_MD5)},
      {HASH_TYPE_SHA1, std::make_shared<Hash>(HASH_TYPE_SHA1)},
      {HASH_TYPE_SHA256, std::make_shared<Hash>(HASH_TYPE_SHA256)},
  };

  auto s = readFile(path,
                    0,
                    HASH_CHUNK_SIZE,
                    false,
                    true,
                    ([&hashes, &mask](std::string& buffer, size_t size) {
                      for (auto& hash : hashes) {
                        if (mask & hash.first) {
                          hash.second->update(&buffer[0], size);
                        }
                      }
                    }));

  MultiHashes mh = {};
  if (!s.ok()) {
    return mh;
  }

  mh.mask = mask;
  if (mask & HASH_TYPE_MD5) {
    mh.md5 = hashes.at(HASH_TYPE_MD5)->digest();
  }
  if (mask & HASH_TYPE_SHA1) {
    mh.sha1 = hashes.at(HASH_TYPE_SHA1)->digest();
  }
  if (mask & HASH_TYPE_SHA256) {
    mh.sha256 = hashes.at(HASH_TYPE_SHA256)->digest();
  }
  return mh;
}

std::string hashFromFile(HashType hash_type, const std::string& path) {
  auto hashes = hashMultiFromFile(hash_type, path);
  if (hash_type == HASH_TYPE_MD5) {
    return hashes.md5;
  } else if (hash_type == HASH_TYPE_SHA1) {
    return hashes.sha1;
  } else {
    return hashes.sha256;
  }
}

namespace tables {

static bool fileCacheExists(const std::string &path);
static bool fileCacheGet(const std::string &path, Row &r);
static bool fileCacheSet(const std::string &path, Row r);

void genHashForFile(const std::string& path,
                    const std::string& dir,
                    QueryContext& context,
                    QueryData& results) {
  // Must provide the path, filename, directory separate from boost path->string
  // helpers to match any explicit (query-parsed) predicate constraints.
  Row r;
  if (fileCacheExists(path)) {
    fileCacheGet(path, r);
  } else if (context.isCached(path)) {
    r = context.getCache(path);
    fileCacheSet(path, r);
  } else {
    auto hashes = hashMultiFromFile(
        HASH_TYPE_MD5 | HASH_TYPE_SHA1 | HASH_TYPE_SHA256, path);

    r["path"] = path;
    r["directory"] = dir;
    r["md5"] = std::move(hashes.md5);
    r["sha1"] = std::move(hashes.sha1);
    r["sha256"] = std::move(hashes.sha256);
    context.setCache(path, r);
    fileCacheSet(path, r);
  }
  results.push_back(r);
}

QueryData genHash(QueryContext& context) {
  QueryData results;
  boost::system::error_code ec;

  // The query must provide a predicate with constraints including path or
  // directory. We search for the parsed predicate constraints with the equals
  // operator.
  auto paths = context.constraints["path"].getAll(EQUALS);
  context.expandConstraints(
      "path",
      LIKE,
      paths,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_ALL | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));

  // Iterate through the file paths, adding the hash results
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path, ec)) {
      continue;
    }

    genHashForFile(path_string, path.parent_path().string(), context, results);
  }

  // Now loop through constraints using the directory column constraint.
  auto directories = context.constraints["directory"].getAll(EQUALS);
  context.expandConstraints(
      "directory",
      LIKE,
      directories,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_FOLDERS | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));

  // Iterate over the directory paths
  for (const auto& directory_string : directories) {
    boost::filesystem::path directory = directory_string;
    if (!boost::filesystem::is_directory(directory, ec)) {
      continue;
    }

    // Iterate over the directory files and generate a hash for each regular
    // file.
    boost::filesystem::directory_iterator begin(directory), end;
    for (; begin != end; ++begin) {
      if (boost::filesystem::is_regular_file(begin->path(), ec)) {
        genHashForFile(
            begin->path().string(), directory_string, context, results);
      }
    }
  }

  return results;
}


/*
 * This is a rought prototype of persistent caching of file hashes
 * TODO: refactor it to a separate singleton
 */

// TODO: make it work on Windows
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <mutex>
#include <unordered_map>

// TODO: make all of these gflags
const int kEvictAtOnce = 1; // how much items to evict when cache is full
const int kCacheSize = 500; // max number of entries the cache holds

struct FileHashCache {
  time_t mtime; // last modification time of the file, # sec since UNIX
  time_t cache_access; // last access to the cache entry, # sec since UNIX
  off_t size; // file size in bytes
  Row r; // cache payload, the whole hash table row
  std::string path; // XXX: tracking it for eviction policy, think of better way
};
static std::mutex cache_mutex;
static std::unordered_map<std::string, FileHashCache> cache;
auto fhccmp = [](FileHashCache *l, FileHashCache *r) {
  return l->cache_access > r->cache_access;
};
static std::priority_queue<FileHashCache *, std::vector<FileHashCache * >, decltype(fhccmp) > lruq(fhccmp);

bool fileCacheExists(const std::string &path) {
  // TODO: we are not writing anything here, boost::shared_mutex maybe?
  std::lock_guard<std::mutex> guard(cache_mutex);

  auto entry = cache.find(path);
  if (entry == cache.end())
    return false;

  struct stat file_stat;
  if (stat(path.c_str(), &file_stat) != 0) {
    // something is wrong with that path, pretend this call never happened and
    // let the caller handle it
    // TODO: handle this error maybe?
    return false;
  }
  if (file_stat.st_size != entry->second.size ||
      file_stat.st_mtime != entry->second.mtime)
    return false;
  return true;
}

bool fileCacheGet(const std::string &path, Row &r) {
  std::lock_guard<std::mutex> guard(cache_mutex);

  auto entry = cache.find(path);
  if (entry == cache.end())
    return false;
  r = entry->second.r;
  entry->second.cache_access = time(0);
  return true;
}

static void fileHashEvict(int nitems = kEvictAtOnce) {
  for (int i = 0; i < nitems; ++i) {
    if (lruq.top()) {
      std::string key = lruq.top()->path;
      lruq.pop();
      if (cache.find(key) != cache.end()) {
        cache.erase(key);
      } // TODO: handle an error in `else'
    }
  }
}

static bool fileCacheSet(const std::string &path, Row r) {
  std::lock_guard<std::mutex> guard(cache_mutex);

  struct stat file_stat;
  if (stat(path.c_str(), &file_stat) != 0) {
    // again, just ignore the error for now, no caching performed of course
    // TODO: handle this error maybe?
    return false;
  }

  if (cache.size() >= kCacheSize)
    fileHashEvict();

  FileHashCache entry = { .mtime = file_stat.st_mtime,
                          .size = file_stat.st_size,
                          .r = std::move(r),
                          .cache_access = time(0),
                          .path = path };
  cache[path] = entry;
  lruq.push(&cache[path]);
  return true;
}


}
}
