/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "osquery/sql/sqlite_util.h"
#include "osquery/sql/virtual_table.h"

#include <osquery/core/plugins/sql.h>

#include <osquery/utils/conversions/castvariant.h>

#include <osquery/core/core.h>
#include <osquery/core/flags.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>

#include <osquery/utils/conversions/split.h>

#include <boost/lexical_cast.hpp>

namespace osquery {

FLAG(string,
     disable_tables,
     "",
     "Comma-delimited list of table names to be disabled");

FLAG(string,
     enable_tables,
     "",
     "Comma-delimited list of table names to be enabled");

FLAG(string, nullvalue, "", "Set string for NULL values, default ''");

using OpReg = QueryPlanner::Opcode::Register;

using SQLiteDBInstanceRef = std::shared_ptr<SQLiteDBInstance>;

/**
 * @brief A map of SQLite status codes to their corresponding message string
 *
 * Details of this map are defined at: http://www.sqlite.org/c3ref/c_abort.html
 */
// clang-format off
const std::map<int, std::string> kSQLiteReturnCodes = {
    {0, "SQLITE_OK"},        {1, "SQLITE_ERROR"},       {2, "SQLITE_INTERNAL"},
    {3, "SQLITE_PERM"},      {4, "SQLITE_ABORT"},       {5, "SQLITE_BUSY"},
    {6, "SQLITE_LOCKED"},    {7, "SQLITE_NOMEM"},       {8, "SQLITE_READONLY"},
    {9, "SQLITE_INTERRUPT"}, {10, "SQLITE_IOERR"},      {11, "SQLITE_CORRUPT"},
    {12, "SQLITE_NOTFOUND"}, {13, "SQLITE_FULL"},       {14, "SQLITE_CANTOPEN"},
    {15, "SQLITE_PROTOCOL"}, {16, "SQLITE_EMPTY"},      {17, "SQLITE_SCHEMA"},
    {18, "SQLITE_TOOBIG"},   {19, "SQLITE_CONSTRAINT"}, {20, "SQLITE_MISMATCH"},
    {21, "SQLITE_MISUSE"},   {22, "SQLITE_NOLFS"},      {23, "SQLITE_AUTH"},
    {24, "SQLITE_FORMAT"},   {25, "SQLITE_RANGE"},      {26, "SQLITE_NOTADB"},
    {27, "SQLITE_NOTICE"},   {28, "SQLITE_WARNING"},    {100, "SQLITE_ROW"},
    {101, "SQLITE_DONE"},
};

const std::map<std::string, std::string> kMemoryDBSettings = {
    {"synchronous", "OFF"},      {"count_changes", "OFF"},
    {"default_temp_store", "0"}, {"auto_vacuum", "FULL"},
    {"journal_mode", "OFF"},     {"cache_size", "0"},
    {"page_count", "0"},
};
// clang-format on

#define OpComparator(x)                                                        \
  { x, QueryPlanner::Opcode(OpReg::P2, INTEGER_TYPE) }
#define Arithmetic(x)                                                          \
  { x, QueryPlanner::Opcode(OpReg::P3, BIGINT_TYPE) }

/**
 * @brief A map from opcode to pair of result register and resultant type.
 *
 * For most opcodes we can deduce a column type based on an interred input
 * to the opcode "function". These come in a few sets, arithmetic operators,
 * comparators, aggregates, and copies.
 */
const std::map<std::string, QueryPlanner::Opcode> kSQLOpcodes = {
    {"Concat", QueryPlanner::Opcode(OpReg::P3, TEXT_TYPE)},
    {"AggStep", QueryPlanner::Opcode(OpReg::P3, BIGINT_TYPE)},
    {"AggStep0", QueryPlanner::Opcode(OpReg::P3, BIGINT_TYPE)},
    {"Integer", QueryPlanner::Opcode(OpReg::P2, INTEGER_TYPE)},
    {"Int64", QueryPlanner::Opcode(OpReg::P2, BIGINT_TYPE)},
    {"String", QueryPlanner::Opcode(OpReg::P2, TEXT_TYPE)},
    {"String8", QueryPlanner::Opcode(OpReg::P2, TEXT_TYPE)},
    {"Or", QueryPlanner::Opcode(OpReg::P3, INTEGER_TYPE)},
    {"And", QueryPlanner::Opcode(OpReg::P3, INTEGER_TYPE)},

    // Arithmetic yields a BIGINT for safety.
    Arithmetic("BitAnd"),
    Arithmetic("BitOr"),
    Arithmetic("ShiftLeft"),
    Arithmetic("ShiftRight"),
    Arithmetic("Add"),
    Arithmetic("Subtract"),
    Arithmetic("Multiply"),
    Arithmetic("Divide"),
    Arithmetic("Remainder"),

    // Comparators result in booleans and are treated as INTEGERs.
    OpComparator("Not"),
    OpComparator("IsNull"),
    OpComparator("NotNull"),
    OpComparator("Ne"),
    OpComparator("Eq"),
    OpComparator("Gt"),
    OpComparator("Le"),
    OpComparator("Lt"),
    OpComparator("Ge"),
    OpComparator("IfNeg"),
    OpComparator("IfNotZero"),
};

RecursiveMutex SQLiteDBInstance::kPrimaryAttachMutex;

/// The SQLiteSQLPlugin implements the "sql" registry for internal/core.
class SQLiteSQLPlugin : public SQLPlugin {
 public:
  /// Execute SQL and store results.
  Status query(const std::string& query,
               QueryData& results,
               bool use_cache) const override;

  /// Introspect, explain, the suspected types selected in an SQL statement.
  Status getQueryColumns(const std::string& query,
                         TableColumns& columns) const override;

  /// Similar to getQueryColumns but return the scanned tables.
  Status getQueryTables(const std::string& query,
                        std::vector<std::string>& tables) const override;

  /// Create a SQLite module and attach (CREATE).
  Status attach(const std::string& name) override;

  /// Detach a virtual table (DROP).
  Status detach(const std::string& name) override;
};

/// SQL provider for osquery internal/core.
REGISTER_INTERNAL(SQLiteSQLPlugin, "sql", "sql");

std::string getStringForSQLiteReturnCode(int code) {
  if (kSQLiteReturnCodes.find(code) != kSQLiteReturnCodes.end()) {
    return kSQLiteReturnCodes.at(code);
  } else {
    std::ostringstream s;
    s << "Error: " << code << " is not a valid SQLite result code";
    return s.str();
  }
}

Status SQLiteSQLPlugin::query(const std::string& query,
                              QueryData& results,
                              bool use_cache) const {
  auto dbc = SQLiteDBManager::get();
  dbc->useCache(use_cache);
  auto result = queryInternal(query, results, dbc);
  dbc->clearAffectedTables();
  return result;
}

Status SQLiteSQLPlugin::getQueryColumns(const std::string& query,
                                        TableColumns& columns) const {
  auto dbc = SQLiteDBManager::get();
  return getQueryColumnsInternal(query, columns, dbc);
}

Status SQLiteSQLPlugin::getQueryTables(const std::string& query,
                                       std::vector<std::string>& tables) const {
  auto dbc = SQLiteDBManager::get();
  QueryPlanner planner(query, dbc);
  tables = planner.tables();
  return Status(0);
}

SQLInternal::SQLInternal(const std::string& query, bool use_cache) {
  auto dbc = SQLiteDBManager::get();
  dbc->useCache(use_cache);
  status_ = queryInternal(query, resultsTyped_, dbc);

  // One of the advantages of using SQLInternal (aside from the Registry-bypass)
  // is the ability to "deep-inspect" the table attributes and actions.
  event_based_ = (dbc->getAttributes() & TableAttributes::EVENT_BASED) != 0;

  dbc->clearAffectedTables();
}

QueryDataTyped& SQLInternal::rowsTyped() {
  return resultsTyped_;
}

const Status& SQLInternal::getStatus() const {
  return status_;
}

bool SQLInternal::eventBased() const {
  return event_based_;
}

// Temporary:  I'm going to move this from sql.cpp to here in change immediately
// following since this is the only place we actually use it (breaking up to
// make CRs smaller)
extern void escapeNonPrintableBytesEx(std::string& str);

class StringEscaperVisitor : public boost::static_visitor<> {
 public:
  void operator()(long long& i) const { // NO-OP
  }

  void operator()(double& d) const { // NO-OP
  }

  void operator()(std::string& str) const {
    escapeNonPrintableBytesEx(str);
  }
};

void SQLInternal::escapeResults() {
  StringEscaperVisitor visitor;
  for (auto& rowTyped : resultsTyped_) {
    for (auto& column : rowTyped) {
      boost::apply_visitor(visitor, column.second);
    }
  }
}

Status SQLiteSQLPlugin::attach(const std::string& name) {
  PluginResponse response;
  auto status =
      Registry::call("table", name, {{"action", "columns"}}, response);
  if (!status.ok()) {
    return status;
  }

  bool is_extension = true;
  auto statement = columnDefinition(response, false, is_extension);

  // Attach requests occurring via the plugin/registry APIs must act on the
  // primary database. To allow this, getConnection can explicitly request the
  // primary instance and avoid the contention decisions.
  auto dbc = SQLiteDBManager::getConnection(true);

  // Attach as an extension, allowing read/write tables
  return attachTableInternal(name, statement, dbc, is_extension);
}

Status SQLiteSQLPlugin::detach(const std::string& name) {
  // Detach requests occurring via the plugin/registry APIs must act on the
  // primary database. To allow this, getConnection can explicitly request the
  // primary instance and avoid the contention decisions.
  auto dbc = SQLiteDBManager::getConnection(true);
  return detachTableInternal(name, dbc);
}

SQLiteDBInstance::SQLiteDBInstance(sqlite3*& db, Mutex& mtx)
    : db_(db), lock_(mtx, boost::try_to_lock) {
  if (lock_.owns_lock()) {
    primary_ = true;
  } else {
    db_ = nullptr;
    VLOG(1) << "DBManager contention: opening transient SQLite database";
    init();
  }
}

static inline void openOptimized(sqlite3*& db) {
  sqlite3_open(":memory:", &db);

  std::string settings;
  for (const auto& setting : kMemoryDBSettings) {
    settings += "PRAGMA " + setting.first + "=" + setting.second + "; ";
  }
  sqlite3_exec(db, settings.c_str(), nullptr, nullptr, nullptr);

  // Register function extensions.
  registerMathExtensions(db);
#if !defined(FREEBSD)
  registerStringExtensions(db);
#endif
#if !defined(SKIP_CARVER)
  registerOperationExtensions(db);
#endif
  registerFilesystemExtensions(db);
  registerHashingExtensions(db);
  registerEncodingExtensions(db);
  registerVersionExtensions(db);
}

void SQLiteDBInstance::init() {
  primary_ = false;
  openOptimized(db_);
}

void SQLiteDBInstance::useCache(bool use_cache) {
  use_cache_ = use_cache;
}

bool SQLiteDBInstance::useCache() const {
  return use_cache_;
}

RecursiveLock SQLiteDBInstance::attachLock() const {
  if (isPrimary()) {
    return RecursiveLock(kPrimaryAttachMutex);
  }
  return RecursiveLock(attach_mutex_);
}

void SQLiteDBInstance::addAffectedTable(
    std::shared_ptr<VirtualTableContent> table) {
  // An xFilter/scan was requested for this virtual table.
  affected_tables_.insert(std::make_pair(table->name, std::move(table)));
}

bool SQLiteDBInstance::tableCalled(VirtualTableContent const& table) {
  return (affected_tables_.count(table.name) > 0);
}

TableAttributes SQLiteDBInstance::getAttributes() const {
  const SQLiteDBInstance* rdbc = this;
  if (isPrimary() && !managed_) {
    // Similarly to clearAffectedTables, the connection may be forwarded.
    rdbc = SQLiteDBManager::getConnection(true).get();
  }

  TableAttributes attributes = TableAttributes::NONE;
  for (const auto& table : rdbc->affected_tables_) {
    attributes = table.second->attributes | attributes;
  }
  return attributes;
}

void SQLiteDBInstance::clearAffectedTables() {
  if (isPrimary() && !managed_) {
    // A primary instance must forward clear requests to the DB manager's
    // 'connection' instance. This is a temporary primary instance.
    SQLiteDBManager::getConnection(true)->clearAffectedTables();
    return;
  }

  for (const auto& table : affected_tables_) {
    table.second->constraints.clear();
    table.second->cache.clear();
    table.second->colsUsed.clear();
    table.second->colsUsedBitsets.clear();
  }
  // Since the affected tables are cleared, there are no more affected tables.
  // There is no concept of compounding tables between queries.
  affected_tables_.clear();
  use_cache_ = false;
}

SQLiteDBInstance::~SQLiteDBInstance() {
  if (!isPrimary() && db_ != nullptr) {
    sqlite3_close(db_);
  } else {
    db_ = nullptr;
  }
}

SQLiteDBManager::SQLiteDBManager() : db_(nullptr) {
  sqlite3_soft_heap_limit64(1);
  setDisabledTables(Flag::getValue("disable_tables"));
  setEnabledTables(Flag::getValue("enable_tables"));
}

bool SQLiteDBManager::isDisabled(const std::string& table_name) {
  bool disabled_set = !Flag::isDefault("disable_tables");
  bool enabled_set = !Flag::isDefault("enable_tables");
  if (!disabled_set && !enabled_set) {
    // We have zero enabled tables and zero disabled tables.
    // As a result, no tables are disabled.
    return false;
  }
  const auto& element_disabled = instance().disabled_tables_.find(table_name);
  const auto& element_enabled = instance().enabled_tables_.find(table_name);
  bool table_disabled = (element_disabled != instance().disabled_tables_.end());
  bool table_enabled = (element_enabled != instance().enabled_tables_.end());

  if (table_disabled) {
    return true;
  }

  if (table_enabled && disabled_set && !table_disabled) {
    return false;
  }

  if (table_enabled && !disabled_set) {
    return false;
  }

  if (enabled_set && !table_enabled) {
    return true;
  }

  if (disabled_set && !table_disabled) {
    return false;
  }

  return true;
}

void SQLiteDBManager::resetPrimary() {
  auto& self = instance();

  WriteLock connection_lock(self.mutex_);
  self.connection_.reset();

  {
    WriteLock create_lock(self.create_mutex_);
    sqlite3_close(self.db_);
    self.db_ = nullptr;
  }
}

void SQLiteDBManager::setDisabledTables(const std::string& list) {
  const auto& tables = split(list, ",");
  disabled_tables_ =
      std::unordered_set<std::string>(tables.begin(), tables.end());
}

void SQLiteDBManager::setEnabledTables(const std::string& list) {
  const auto& tables = split(list, ",");
  enabled_tables_ =
      std::unordered_set<std::string>(tables.begin(), tables.end());
}

SQLiteDBInstanceRef SQLiteDBManager::getUnique() {
  auto instance = std::make_shared<SQLiteDBInstance>();
  attachVirtualTables(instance);
  return instance;
}

SQLiteDBInstanceRef SQLiteDBManager::getConnection(bool primary) {
  auto& self = instance();
  WriteLock lock(self.create_mutex_);

  if (self.db_ == nullptr) {
    // Create primary SQLite DB instance.
    openOptimized(self.db_);
    self.connection_ = SQLiteDBInstanceRef(new SQLiteDBInstance(self.db_));
    attachVirtualTables(self.connection_);
  }

  // Internal usage may request the primary connection explicitly.
  if (primary) {
    return self.connection_;
  }

  // Create a 'database connection' for the managed database instance.
  auto instance = std::make_shared<SQLiteDBInstance>(self.db_, self.mutex_);
  if (!instance->isPrimary()) {
    attachVirtualTables(instance);
  }
  return instance;
}

SQLiteDBManager::~SQLiteDBManager() {
  connection_ = nullptr;
  if (db_ != nullptr) {
    sqlite3_close(db_);
    db_ = nullptr;
  }
}

QueryPlanner::QueryPlanner(const std::string& query,
                           const SQLiteDBInstanceRef& instance) {
  QueryData plan;
  queryInternal("EXPLAIN QUERY PLAN " + query, plan, instance);
  queryInternal("EXPLAIN " + query, program_, instance);

  for (const auto& row : plan) {
    auto details = osquery::split(row.at("detail"));
    if (details.size() > 2 && details[0] == "SCAN") {
      tables_.push_back(details[2]);
    }
  }
}

Status QueryPlanner::applyTypes(TableColumns& columns) {
  std::map<size_t, ColumnType> column_types;
  for (const auto& row : program_) {
    if (row.at("opcode") == "ResultRow") {
      // The column parsing is finished.
      auto k = boost::lexical_cast<size_t>(row.at("p1"));
      for (const auto& type : column_types) {
        if (type.first - k < columns.size()) {
          std::get<1>(columns[type.first - k]) = type.second;
        }
      }
    }

    if (row.at("opcode") == "Copy") {
      // Copy P1 -> P1 + P3 into P2 -> P2 + P3.
      auto from = boost::lexical_cast<size_t>(row.at("p1"));
      auto to = boost::lexical_cast<size_t>(row.at("p2"));
      auto size = boost::lexical_cast<size_t>(row.at("p3"));
      for (size_t i = 0; i <= size; i++) {
        if (column_types.count(from + i)) {
          column_types[to + i] = std::move(column_types[from + i]);
          column_types.erase(from + i);
        }
      }
    } else if (row.at("opcode") == "Cast") {
      auto value = boost::lexical_cast<size_t>(row.at("p1"));
      auto to = boost::lexical_cast<size_t>(row.at("p2"));
      switch (to) {
      case 'A': // BLOB
        column_types[value] = BLOB_TYPE;
        break;
      case 'B': // TEXT
        column_types[value] = TEXT_TYPE;
        break;
      case 'C': // NUMERIC
        // We don't exactly have an equivalent to NUMERIC (which includes such
        // things as DATETIME and DECIMAL
        column_types[value] = UNKNOWN_TYPE;
        break;
      case 'D': // INTEGER
        column_types[value] = BIGINT_TYPE;
        break;
      case 'E': // REAL
        column_types[value] = DOUBLE_TYPE;
        break;
      default:
        column_types[value] = UNKNOWN_TYPE;
        break;
      }
    }

    if (kSQLOpcodes.count(row.at("opcode"))) {
      const auto& op = kSQLOpcodes.at(row.at("opcode"));
      auto k = boost::lexical_cast<size_t>(row.at(Opcode::regString(op.reg)));
      column_types[k] = op.type;
    }
  }

  return Status(0);
}

// Wrapper for legacy method until all uses can be replaced
Status queryInternal(const std::string& query,
                     QueryData& results,
                     const SQLiteDBInstanceRef& instance) {
  QueryDataTyped typedResults;
  Status status = queryInternal(query, typedResults, instance);
  if (status.ok()) {
    results.reserve(typedResults.size());
    for (const auto& row : typedResults) {
      Row r;
      for (const auto& col : row) {
        r[col.first] = castVariant(col.second);
      }
      results.push_back(std::move(r));
    }
  }
  return status;
}

Status readRows(sqlite3_stmt* prepared_statement,
                QueryDataTyped& results,
                const SQLiteDBInstanceRef& instance) {
  // Do nothing with a null prepared_statement (eg, if the sql was just
  // whitespace)
  if (prepared_statement == nullptr) {
    return Status::success();
  }
  int rc = sqlite3_step(prepared_statement);
  /* if we have a result set row... */
  if (SQLITE_ROW == rc) {
    // First collect the column names
    int num_columns = sqlite3_column_count(prepared_statement);
    std::vector<std::string> colNames;
    colNames.reserve(num_columns);
    for (int i = 0; i < num_columns; i++) {
      colNames.push_back(sqlite3_column_name(prepared_statement, i));
    }

    do {
      RowTyped row;
      for (int i = 0; i < num_columns; i++) {
        switch (sqlite3_column_type(prepared_statement, i)) {
        case SQLITE_INTEGER:
          row[colNames[i]] = static_cast<long long>(
              sqlite3_column_int64(prepared_statement, i));
          break;
        case SQLITE_FLOAT:
          row[colNames[i]] = sqlite3_column_double(prepared_statement, i);
          break;
        case SQLITE_NULL:
          row[colNames[i]] = FLAGS_nullvalue;
          break;
        default:
          // Everything else (SQLITE_TEXT, SQLITE3_TEXT, SQLITE_BLOB) is
          // obtained/conveyed as text/string
          row[colNames[i]] = std::string(reinterpret_cast<const char*>(
              sqlite3_column_text(prepared_statement, i)));
        }
      }
      results.push_back(std::move(row));
      rc = sqlite3_step(prepared_statement);
    } while (SQLITE_ROW == rc);
  }
  if (rc != SQLITE_DONE) {
    auto s = Status::failure(sqlite3_errmsg(instance->db()));
    sqlite3_finalize(prepared_statement);
    return s;
  }

  rc = sqlite3_finalize(prepared_statement);
  if (rc != SQLITE_OK) {
    return Status::failure(sqlite3_errmsg(instance->db()));
  }

  return Status::success();
}

Status queryInternal(const std::string& query,
                     QueryDataTyped& results,
                     const SQLiteDBInstanceRef& instance) {
  sqlite3_stmt* prepared_statement{nullptr}; /* Statement to execute. */

  int rc = SQLITE_OK; /* Return Code */
  const char* leftover_sql = nullptr; /* Tail of unprocessed SQL */
  const char* sql = query.c_str(); /* SQL to be processed */

  /* The big while loop.  One iteration per statement */
  while ((sql[0] != '\0') && (SQLITE_OK == rc)) {
    const auto lock = instance->attachLock();

    // Trim leading whitespace
    while (isspace(sql[0])) {
      sql++;
    }
    rc = sqlite3_prepare_v2(
        instance->db(), sql, -1, &prepared_statement, &leftover_sql);
    if (rc != SQLITE_OK) {
      Status s = Status::failure(sqlite3_errmsg(instance->db()));
      sqlite3_finalize(prepared_statement);
      return s;
    }

    Status s = readRows(prepared_statement, results, instance);
    if (!s.ok()) {
      return s;
    }

    sql = leftover_sql;
  } /* end while */
  sqlite3_db_release_memory(instance->db());
  return Status::success();
}

Status getQueryColumnsInternal(const std::string& q,
                               TableColumns& columns,
                               const SQLiteDBInstanceRef& instance) {
  Status status = Status();
  TableColumns results;
  {
    auto lock = instance->attachLock();

    // Turn the query into a prepared statement
    sqlite3_stmt* stmt{nullptr};
    auto rc = sqlite3_prepare_v2(instance->db(),
                                 q.c_str(),
                                 static_cast<int>(q.length() + 1),
                                 &stmt,
                                 nullptr);
    if (rc != SQLITE_OK || stmt == nullptr) {
      auto s = Status::failure(sqlite3_errmsg(instance->db()));
      if (stmt != nullptr) {
        sqlite3_finalize(stmt);
      }
      return s;
    }

    // Get column count
    auto num_columns = sqlite3_column_count(stmt);
    results.reserve(num_columns);

    // Get column names and types
    bool unknown_type = false;
    for (int i = 0; i < num_columns; ++i) {
      auto col_name = sqlite3_column_name(stmt, i);
      auto col_type = sqlite3_column_decltype(stmt, i);

      if (col_name == nullptr) {
        status = Status(1, "Could not get column type");
        break;
      }

      if (col_type == nullptr) {
        // Types are only returned for table columns (not expressions).
        col_type = "UNKNOWN";
        unknown_type = true;
      }
      results.push_back(std::make_tuple(
          col_name, columnTypeName(col_type), ColumnOptions::DEFAULT));
    }

    // An unknown type means we have to parse the plan and SQLite opcodes.
    if (unknown_type) {
      QueryPlanner planner(q, instance);
      planner.applyTypes(results);
    }
    sqlite3_finalize(stmt);
  }

  if (status.ok()) {
    columns = std::move(results);
  }

  return status;
}
} // namespace osquery
