/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>
#include <OSLog/OSLog.h>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

#include <boost/algorithm/string/replace.hpp>

namespace ba = boost::algorithm;

namespace osquery {
namespace tables {

const std::map<ConstraintOperator, NSPredicateOperatorType> kSupportedOps = {
    {EQUALS, NSEqualToPredicateOperatorType},
    {GREATER_THAN, NSGreaterThanPredicateOperatorType},
    {GREATER_THAN_OR_EQUALS, NSGreaterThanOrEqualToPredicateOperatorType},
    {LESS_THAN, NSLessThanPredicateOperatorType},
    {LESS_THAN_OR_EQUALS, NSLessThanOrEqualToPredicateOperatorType},
    {LIKE, NSLikePredicateOperatorType}};

const std::map<std::string, std::string> kColumnToOSLogEntryProp = {
    {"timestamp", "date"},
    {"message", "composedMessage"},
    {"storage", "storeCategory"},
    {"activity", "activityIdentifier"},
    {"process", "process"},
    {"pid", "processIdentifier"},
    {"sender", "sender"},
    {"tid", "threadIdentifier"},
    {"subsystem", "subsystem"},
    {"category", "category"}};

const std::map<std::string, bool> kColumnIsNumeric = {{"timestamp", false},
                                                      {"message", false},
                                                      {"storage", true},
                                                      {"activity", true},
                                                      {"process", false},
                                                      {"pid", true},
                                                      {"sender", false},
                                                      {"tid", true},
                                                      {"subsystem", false},
                                                      {"category", false}};

std::string convertLikeExpr(const std::string& value) {
  // for the LIKE operator in NSPredicates, '*' matches 0 or more characters
  //   and '?' matches a single character
  std::string res = ba::replace_all_copy(value, "%", "*");
  ba::replace_all(res, "_", "?");
  return res;
}

void addQueryOp(NSMutableArray* preds,
                const std::string& key,
                const std::string& value,
                ConstraintOperator op) {
  if (kSupportedOps.count(op) > 0 && kColumnToOSLogEntryProp.count(key) > 0) {
    std::string modified_val = value;
    std::string modified_key = kColumnToOSLogEntryProp.at(key);
    if (op == LIKE) {
      modified_val = convertLikeExpr(value);
    }
    NSExpression* keyExp = [NSExpression
        expressionForKeyPath:[NSString
                                 stringWithUTF8String:modified_key.c_str()]];
    NSString* valStr = [NSString stringWithUTF8String:modified_val.c_str()];

    NSExpression* valExp = nil;
    if (key == "timestamp") {
      double provided_timestamp = [valStr doubleValue];
      valExp = [NSExpression
          expressionForConstantValue:
              [NSDate dateWithTimeIntervalSince1970:provided_timestamp]];
    } else if (kColumnIsNumeric.at(key)) {
      valExp =
          [NSExpression expressionWithFormat:@"%lld", [valStr longLongValue]];
    } else {
      valExp = [NSExpression expressionForConstantValue:valStr];
    }

    NSPredicate* pred = [NSComparisonPredicate
        predicateWithLeftExpression:keyExp
                    rightExpression:valExp
                           modifier:NSDirectPredicateModifier
                               type:kSupportedOps.at(op)
                            options:0];
    [preds addObject:pred];
  }
}

QueryData genUnifiedLog(QueryContext& queryContext) {
  QueryData results;
  if (!@available(macOS 10.15, *)) {
    VLOG(1) << "OSLog framework is not available";
    return {};
  }

  @autoreleasepool {
    NSError* error = nil;
    OSLogStore* logstore = [OSLogStore localStoreAndReturnError:&error];
    if (error != nil) {
      TLOG << "error getting handle to log store: "
           << [[error localizedDescription] UTF8String];
      return {};
    }

    OSLogPosition* position = nil;

    // the timestamp column can be used to aggressively filter
    // results returned from the log store
    if (queryContext.hasConstraint("timestamp", GREATER_THAN) ||
        queryContext.hasConstraint("timestamp", GREATER_THAN_OR_EQUALS)) {
      std::string start_time;
      if (queryContext.hasConstraint("timestamp", GREATER_THAN)) {
        start_time =
            *queryContext.constraints["timestamp"].getAll(GREATER_THAN).begin();
      } else {
        start_time = *queryContext.constraints["timestamp"]
                          .getAll(GREATER_THAN_OR_EQUALS)
                          .begin();
      }

      double provided_timestamp =
          [[NSString stringWithUTF8String:start_time.c_str()] doubleValue];
      NSDate* provided_date =
          [NSDate dateWithTimeIntervalSince1970:provided_timestamp];

      position = [logstore positionWithDate:provided_date];
    }

    // grab all the supported columns used in simple constraints and make a
    // compound predicate out of them.
    NSMutableArray* subpredicates = [[NSMutableArray alloc] init];
    for (const auto& it : queryContext.constraints) {
      const std::string& key = it.first;
      for (const auto& constraint : it.second.getAll()) {
        addQueryOp(subpredicates,
                   key,
                   constraint.expr,
                   static_cast<ConstraintOperator>(constraint.op));
      }
    }

    NSPredicate* predicate =
        [NSCompoundPredicate andPredicateWithSubpredicates:subpredicates];

    // enumerate the entries in ascending order by timestamp
    OSLogEnumeratorOptions option = 0;

    OSLogEnumerator* enumerator =
        [logstore entriesEnumeratorWithOptions:option
                                      position:position
                                     predicate:predicate
                                         error:&error];
    if (error != nil) {
      TLOG << "error enumerating entries in system log: "
           << [[error localizedDescription] UTF8String];
      return {};
    }
    for (OSLogEntryLog* entry in enumerator) {
      Row r;
      r["timestamp"] = BIGINT([[entry date] timeIntervalSince1970]);
      r["message"] = TEXT([[entry composedMessage] UTF8String]);
      r["storage"] = INTEGER([entry storeCategory]);

      if ([entry respondsToSelector:@selector(activityIdentifier)]) {
        r["activity"] = INTEGER([entry activityIdentifier]);
        r["process"] = TEXT([[entry process] UTF8String]);
        r["pid"] = INTEGER([entry processIdentifier]);
        r["sender"] = TEXT([[entry sender] UTF8String]);
        r["tid"] = INTEGER([entry threadIdentifier]);
      }

      if ([entry respondsToSelector:@selector(subsystem)]) {
        NSString* subsystem = [entry subsystem];
        if (subsystem != nil) {
          r["subsystem"] = TEXT([subsystem UTF8String]);
        }
        NSString* category = [entry category];
        if (category != nil) {
          r["category"] = TEXT([category UTF8String]);
        }
      }
      if ([entry respondsToSelector:@selector(level)]) {
        const char* logLevelNames[] = {
            [OSLogEntryLogLevelUndefined] = "undefined",
            [OSLogEntryLogLevelDebug] = "debug",
            [OSLogEntryLogLevelInfo] = "info",
            [OSLogEntryLogLevelNotice] = "default",
            [OSLogEntryLogLevelError] = "error",
            [OSLogEntryLogLevelFault] = "fault",
        };

        r["level"] = TEXT(logLevelNames[[entry level]]);
      }
      results.push_back(r);
    }
  }

  return results;
}

} // namespace tables
} // namespace osquery
