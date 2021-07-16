/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <vector>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/system_utils.h>
#include <osquery/utils/scope_guard.h>
#include <osquery/utils/system/system.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

#include <boost/algorithm/string.hpp>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace osquery {
namespace tables {

extern const std::string kSSHUserKeysDir = ".ssh";

const std::string kOpenSshHeader = "-----BEGIN OPENSSH PRIVATE KEY-----";

// The first bytes of an OpenSSH key are |key type|length of cipher name|cipher
// name| so all unencrypted ed25519 keys should start with the value below
// (encoded in base64) This magic string is (hex-ified):
//  6f 70 65 6e 73 73 68 2d 6b 65 79 2d 76 31 00 00 00 00 04 6e 6f 6e 65
// |--------------------------------------------|-----------|----------|
// | o  p  e  n  s  s  h  -  k  e  y  -  v  1 \0|          4| n  o  n e|
const std::string kOpenSshUnencryptedPrefix = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU";

// openssl can't currently parse the new openssh keys
bool isOpenSSHKey(const std::string& keys_content) {
  return boost::starts_with(keys_content, kOpenSshHeader);
}

// `true` if the openssh key is encrypted, `false` otherwise.
bool isOpenSSHKeyEncrypted(const std::string& keys_content) {
  const std::string prefix = keys_content.substr(
      kOpenSshHeader.size() + 1, kOpenSshUnencryptedPrefix.size());
  return prefix != kOpenSshUnencryptedPrefix;
}

// parsePrivateKey returns true iff the key is valid.
// Tries to parse the .PEM using openssl. If that fails, it checks
// if it's an openssh key.
bool parsePrivateKey(const std::string& keys_content,
                     int& key_type,
                     bool& is_encrypted) {
  BIO* bio_stream = BIO_new(BIO_s_mem());
  auto const bio_stream_guard =
      scope_guard::create([bio_stream]() { BIO_free(bio_stream); });
  BIO_write(bio_stream, keys_content.c_str(), keys_content.size());
  if (bio_stream == nullptr) {
    return false;
  }

  // PEM_read_bio_PrivateKey calls passwordCallback
  // if the private key is encrypted. We don't care what the key is;
  // only whether or not it's encrypted.
  auto passwordCallback = [](char*, int, int, void* u) {
    bool* encrypted_ptr = reinterpret_cast<bool*>(u);
    *encrypted_ptr = true;
    return -1; // let openssl know that the passwordCallback failed
  };

  bool encrypted = false;
  auto pkey = PEM_read_bio_PrivateKey(bio_stream,
                                      nullptr,
                                      passwordCallback,
                                      reinterpret_cast<void*>(&encrypted));
  is_encrypted = encrypted;
  auto const pkey_guard =
      scope_guard::create([pkey]() { EVP_PKEY_free(pkey); });

  if (pkey == nullptr) {
    if (encrypted) {
      key_type = EVP_PKEY_NONE;
      return true;
    }
    // A later version of OpenSSL may add support for openssh keys. If so,
    // we can delete this conditional.
    if (isOpenSSHKey(keys_content)) {
      key_type = EVP_PKEY_NONE;
      is_encrypted = isOpenSSHKeyEncrypted(keys_content);
      return true;
    }
    // if openssl can't parse the key and it doesn't start with the openssh
    // header, it's proabably not a valid key.
    return false;
  }
  key_type = EVP_PKEY_base_id(pkey);
  return true;
}

std::string keyTypeAsString(int key_type) {
  switch (key_type) {
  case EVP_PKEY_RSA:
  case EVP_PKEY_RSA2:
    return "rsa";
  case EVP_PKEY_DSA:
  case EVP_PKEY_DSA1:
  case EVP_PKEY_DSA2:
  case EVP_PKEY_DSA3:
  case EVP_PKEY_DSA4:
    return "dsa";
  case EVP_PKEY_DH:
  case EVP_PKEY_DHX:
    return "dh";
  case EVP_PKEY_EC:
    return "ec";
  case EVP_PKEY_HMAC:
    return "hmac";
  case EVP_PKEY_CMAC:
    return "cmac";
  default:
    return "";
  }
}

void genSSHkeyForHosts(const std::string& uid,
                       const std::string& gid,
                       const std::string& directory,
                       QueryData& results,
                       Logger& logger) {
  // Get list of files in directory
  boost::filesystem::path keys_dir = directory;
  keys_dir /= kSSHUserKeysDir;
  std::vector<std::string> files_list;
  auto status = listFilesInDirectory(keys_dir, files_list, false);
  if (!status.ok()) {
    return;
  }

  // Go through each file
  for (const auto& kfile : files_list) {
    std::string keys_content;
    auto s = forensicReadFile(kfile, keys_content, false, false);
    if (!s.ok()) {
      // Cannot read a specific keys file.
      logger.log(google::GLOG_WARNING, s.getMessage());
      logger.vlog(1, s.getMessage());
      continue;
    }
    int key_type;
    bool encrypted;
    bool parsed = parsePrivateKey(keys_content, key_type, encrypted);
    if (parsed) {
      Row r;
      r["pid_with_namespace"] = "0";
      r["uid"] = uid;
      r["path"] = kfile;
      r["encrypted"] = encrypted ? "1" : "0";
      r["key_type"] = keyTypeAsString(key_type);
      results.push_back(r);
    }
  }
}

QueryData getUserSshKeysImpl(QueryContext& context, Logger& logger) {
  QueryData results;

  // Iterate over each user
  auto users = usersFromContext(context);
  for (const auto& row : users) {
    auto uid = row.find("uid");
    auto gid = row.find("gid");
    auto directory = row.find("directory");
    if (uid != row.end() && gid != row.end() && directory != row.end()) {
      genSSHkeyForHosts(
          uid->second, gid->second, directory->second, results, logger);
    }
  }

  return results;
}

QueryData getUserSshKeys(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(context, "user_ssh_keys", getUserSshKeysImpl);
  } else {
    GLOGLogger logger;
    return getUserSshKeysImpl(context, logger);
  }
}
} // namespace tables
} // namespace osquery
