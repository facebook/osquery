/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#import <OpenDirectory/OpenDirectory.h>
#include <membership.h>

#include <osquery/tables/system/user_groups.h>
#include <osquery/utils/conversions/tryto.h>

namespace osquery {
namespace tables {

/**
 * @brief Lookup usernames/groupnames or a single name's hidden value.
 *
 * @param record_type Either usernames or groupnames.
 * @param record Look for a specific record by name or nil for all.
 * @param [out] names A list of discovered names and hidden status.
 */
void genODEntries(ODRecordType record_type,
                  NSString* record,
                  std::map<std::string, bool>& names) {
  ODSession* session = [ODSession defaultSession];
  NSError* err = nullptr;
  ODNode* root = [ODNode nodeWithSession:session
                                    name:@"/Local/Default"
                                   error:&err];
  if (err != nullptr) {
    TLOG << "Error with OpenDirectory node: "
         << std::string([[err localizedDescription] UTF8String]);
    return;
  }

  ODQuery* query = [ODQuery queryWithNode:root
                           forRecordTypes:record_type
                                attribute:kODAttributeTypeUniqueID
                                matchType:kODMatchEqualTo
                              queryValues:record
                         returnAttributes:kODAttributeTypeAllTypes
                           maximumResults:0
                                    error:&err];
  if (err != nullptr) {
    TLOG << "Error with OpenDirectory query: "
         << std::string([[err localizedDescription] UTF8String]);
    return;
  }

  // Obtain the results synchronously, not good for very large sets.
  NSArray* od_results = [query resultsAllowingPartial:NO error:&err];
  if (err != nullptr) {
    TLOG << "Error with OpenDirectory results: "
         << std::string([[err localizedDescription] UTF8String]);
    return;
  }

  // Missing or invalid IsHidden is equivalent to IsHidden: 0.
  for (ODRecord* re in od_results) {
    bool isHidden = false;
    auto isHiddenValue = [re valuesForAttribute:@"dsAttrTypeNative:IsHidden"
                                          error:&err];
    if (isHiddenValue.count >= 1) {
      isHidden =
          tryTo<bool>(std::string([isHiddenValue[0] UTF8String])).takeOr(false);
    }
    names[[[re recordName] UTF8String]] = isHidden;
  }
}

QueryData genGroups(QueryContext& context) {
  QueryData results;
  @autoreleasepool {
    if (context.constraints["gid"].exists(EQUALS)) {
      auto gids = context.constraints["gid"].getAll<long long>(EQUALS);
      for (const auto& gid : gids) {
        struct group* grp = getgrgid(gid);
        if (grp == nullptr) {
          continue;
        }

        std::map<std::string, bool> groupnames;
        id groupname = [NSString stringWithUTF8String:grp->gr_name];
        genODEntries(kODRecordTypeGroups, groupname, groupnames);

        Row r;
        r["groupname"] = grp->gr_name;
        r["is_hidden"] = INTEGER(groupnames[r["groupname"]]);
        r["gid"] = BIGINT(grp->gr_gid);
        r["gid_signed"] = BIGINT((int32_t)grp->gr_gid);
        results.push_back(r);
      }
    } else {
      std::map<std::string, bool> groupnames;
      genODEntries(kODRecordTypeGroups, nil, groupnames);
      for (const auto& groupname : groupnames) {
        struct group* grp = getgrnam(groupname.first.c_str());
        if (grp == nullptr) {
          continue;
        }

        Row r;
        r["groupname"] = groupname.first;
        r["is_hidden"] = INTEGER(groupname.second);
        r["gid"] = BIGINT(grp->gr_gid);
        r["gid_signed"] = BIGINT((int32_t)grp->gr_gid);
        results.push_back(r);
      }
    }
  }
  return results;
}

void genUserRow(Row& r, const passwd* pwd) {
  r["uid"] = BIGINT(pwd->pw_uid);
  r["gid"] = BIGINT(pwd->pw_gid);
  r["uid_signed"] = BIGINT((int32_t)pwd->pw_uid);
  r["gid_signed"] = BIGINT((int32_t)pwd->pw_gid);
  r["description"] = TEXT(pwd->pw_gecos);
  r["directory"] = TEXT(pwd->pw_dir);
  r["shell"] = TEXT(pwd->pw_shell);

  uuid_t uuid = {0};
  uuid_string_t uuid_string = {0};

  // From the docs: mbr_uid_to_uuid will always succeed and may return a
  // synthesized UUID with the prefix FFFFEEEE-DDDD-CCCC-BBBB-AAAAxxxxxxxx,
  // where 'xxxxxxxx' is a hex conversion of the UID.
  mbr_uid_to_uuid(pwd->pw_uid, uuid);

  uuid_unparse(uuid, uuid_string);
  r["uuid"] = TEXT(uuid_string);
}

QueryData genUsers(QueryContext& context) {
  QueryData results;
  @autoreleasepool {
    if (context.constraints["uid"].exists(EQUALS)) {
      auto uids = context.constraints["uid"].getAll<long long>(EQUALS);
      for (const auto& uid : uids) {
        struct passwd* pwd = getpwuid(uid);
        if (pwd == nullptr) {
          continue;
        }

        std::map<std::string, bool> usernames;
        id username = [NSString stringWithUTF8String:pwd->pw_name];
        genODEntries(kODRecordTypeUsers, username, usernames);

        Row r;
        r["username"] = pwd->pw_name;
        r["is_hidden"] = INTEGER(usernames[r["username"]]);
        genUserRow(r, pwd);
        results.push_back(r);
      }
    } else {
      std::map<std::string, bool> usernames;
      genODEntries(kODRecordTypeUsers, nil, usernames);
      for (const auto& username : usernames) {
        struct passwd* pwd = getpwnam(username.first.c_str());
        if (pwd == nullptr) {
          continue;
        }

        Row r;
        r["username"] = pwd->pw_name;
        r["is_hidden"] = INTEGER(usernames[r["username"]]);
        genUserRow(r, pwd);
        results.push_back(r);
      }
    }
  }
  return results;
}

QueryData genUserGroups(QueryContext& context) {
  QueryData results;
  @autoreleasepool {
    if (context.constraints["uid"].exists(EQUALS)) {
      // Use UID as the index.
      auto uids = context.constraints["uid"].getAll<long long>(EQUALS);
      for (const auto& uid : uids) {
        struct passwd* pwd = getpwuid(uid);
        if (pwd != nullptr) {
          user_t<int, int> user;
          user.name = pwd->pw_name;
          user.uid = pwd->pw_uid;
          user.gid = pwd->pw_gid;
          getGroupsForUser<int, int>(results, user);
        }
      }
    } else {
      std::map<std::string, bool> usernames;
      genODEntries(kODRecordTypeUsers, nil, usernames);
      for (const auto& username : usernames) {
        struct passwd* pwd = getpwnam(username.first.c_str());
        if (pwd != nullptr) {
          user_t<int, int> user;
          user.name = pwd->pw_name;
          user.uid = pwd->pw_uid;
          user.gid = pwd->pw_gid;
          getGroupsForUser<int, int>(results, user);
        }
      }
    }
  }
  return results;
}
} // namespace tables
} // namespace osquery
