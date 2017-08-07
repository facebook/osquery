/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

namespace osquery {

/// Master strict mode key
const std::string kStrictMode = "strict_mode";
/// JSON/DB key for public key
const std::string kStrictModePublicKey = "public_key";
/// JSON/DB key for protected tables
const std::string kStrictModeProtectedTables = "protected_tables";
/// JSON/DB key for protected tables signature
const std::string kStrictModeProtectedTablesSignature =
    "protected_tables_signature";
/// JSON/DB key for UUID signing
const std::string kStrictModeUUIDSigning = "uuid_signing";
/// JSON/DB key for counter mode
const std::string kStrictModeCounterMode = "counter_mode";

/*
 * @brief Verify a signature for a message with a given key
 *
 * @param b64Pub The public key to use
 * @param b64Sig The signature generated from the private key
 * @param message The message to verify the integrity of
 * @return A status about the result of the verification
 */
Status verifySignature(const std::string& b64Pub,
                       const std::string& b64Sig,
                       const std::string& message);

/*
 * @brief Verify a signature using the strict mode key
 *
 * @param b64Sig The signature generated from the private key
 * @param message The message to verify the integrity of
 * @return A status about the result of the verification
 */
Status verifyStrictSignature(const std::string& b64Sig,
                             const std::string& message);

/*
 * @brief Verify a query signature respecting UUID and counter settings
 *
 * @param b64Sig The signature generated from the private key
 * @param query The query the signature is for
 * @return A status about the result of the verification
 */
Status verifyQuerySignature(const std::string& b64Sig,
                            const std::string& query);

/*
 * @brief Does this query contain protected tables
 *
 * @param query The query the signature is for
 * @return True if any table is protected, false otherwise
 */
bool doesQueryRequireSignature(const std::string& query);
}
