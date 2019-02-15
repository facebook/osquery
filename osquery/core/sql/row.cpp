/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#include "row.h"

namespace rj = rapidjson;

namespace osquery {

Status serializeRow(const Row& r,
                    const ColumnNames& cols,
                    JSON& doc,
                    rj::Value& obj) {
  if (cols.empty()) {
    for (const auto& i : r) {
      doc.addRef(i.first, i.second, obj);
    }
  } else {
    for (const auto& c : cols) {
      auto i = r.find(c);
      if (i != r.end()) {
        doc.addRef(c, i->second, obj);
      }
    }
  }

  return Status();
}

class DocAppenderVisitor : public boost::static_visitor<> {
 public:
  DocAppenderVisitor(JSON& dc, rj::Value& ob) : doc(dc), obj(ob) {}
  void operator()(const std::string& key, const long long& i) const {
    doc.add(key, i, obj);
  }

  void operator()(const std::string& key, const double& d) const {
    doc.add(key, d, obj);
  }

  void operator()(const std::string& key, const std::string& str) const {
    doc.addRef(key, str, obj);
  }

 private:
  JSON& doc;
  rj::Value& obj;
};

Status serializeRow(const RowTyped& r,
                    const ColumnNames& cols,
                    JSON& doc,
                    rj::Value& obj) {
  DocAppenderVisitor visitor(doc, obj);

  if (cols.empty()) {
    for (const auto& i : r) {
      boost::apply_visitor([&doc, &obj, &key = i.first](
                               auto value) { doc.add(key, value, obj); },
                           i.second);
    }
  } else {
    for (const auto& c : cols) {
      auto i = r.find(c);
      if (i != r.end()) {
        boost::apply_visitor(
            [&doc, &obj, &c](auto value) { doc.add(c, value, obj); },
            i->second);
      }
    }
  }

  return Status();
}

Status serializeRowJSON(const RowTyped& r, std::string& json) {
  auto doc = JSON::newObject();

  // An empty column list will traverse the row map.
  ColumnNames cols;
  auto status = serializeRow(r, cols, doc, doc.doc());
  if (!status.ok()) {
    return status;
  }
  return doc.toString(json);
}

Status serializeRowJSON(const Row& r, std::string& json) {
  auto doc = JSON::newObject();

  // An empty column list will traverse the row map.
  ColumnNames cols;
  auto status = serializeRow(r, cols, doc, doc.doc());
  if (!status.ok()) {
    return status;
  }
  return doc.toString(json);
}

Status deserializeRow(const rj::Value& doc, Row& r) {
  if (!doc.IsObject()) {
    return Status(1);
  }

  for (const auto& i : doc.GetObject()) {
    std::string name(i.name.GetString());
    if (!name.empty() && i.value.IsString()) {
      r[name] = i.value.GetString();
    }
  }
  return Status();
}

Status deserializeRow(const rj::Value& doc, RowTyped& r) {
  if (!doc.IsObject()) {
    return Status(1);
  }

  for (const auto& i : doc.GetObject()) {
    std::string name(i.name.GetString());
    if (!name.empty()) {
      if (i.value.IsString()) {
        r[name] = i.value.GetString();
      } else if (i.value.IsDouble()) {
        r[name] = i.value.GetDouble();
      } else if (i.value.IsInt64()) {
        // Cast required for linux-x86_64
        r[name] = (long long)i.value.GetInt64();
      }
    }
  }
  return Status();
}

Status deserializeRowJSON(const std::string& json, Row& r) {
  auto doc = JSON::newObject();
  if (!doc.fromString(json) || !doc.doc().IsObject()) {
    return Status(1, "Cannot deserializing JSON");
  }
  return deserializeRow(doc.doc(), r);
}

Status deserializeRowJSON(const std::string& json, RowTyped& r) {
  auto doc = JSON::newObject();
  if (!doc.fromString(json) || !doc.doc().IsObject()) {
    return Status(1, "Cannot deserializing JSON");
  }
  return deserializeRow(doc.doc(), r);
}

} // namespace osquery
