# Copyright 2004-present Facebook. All Rights Reserved.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import ast
import jinja2
import logging
import os
import sys

# set DEVELOPING to True for debug statements
DEVELOPING = False

# the log format for the logging module
LOG_FORMAT = "%(levelname)s [Line %(lineno)d]: %(message)s"

# HEADER_TEMPLATE is the jinja template used to generate the virtual table
# header file
HEADER_TEMPLATE = """// Copyright 2004-present Facebook. All Rights Reserved.

/*
** This file is generated. Do not modify it manually!
*/

#ifndef OSQUERY_TABLES_{{table_name.upper()}}_H
#define OSQUERY_TABLES_{{table_name.upper()}}_H

#include <string>
#include <vector>

#include "osquery/sqlite3.h"
#include "osquery/tables/base.h"

namespace osquery { namespace tables {

struct sqlite3_{{table_name}} {
  int n;
{% for col in schema %}\
  std::vector<{{col.type}}> {{col.name}};
{% endfor %}\
};

extern const std::string
  sqlite3_{{table_name}}_create_table_statement;

int sqlite3_{{table_name}}_create(
  sqlite3 *db,
  const char *zName,
  sqlite3_{{table_name}} **ppReturn
);

int {{table_name}}Create(
  sqlite3 *db,
  void *pAux,
  int argc,
  const char *const *argv,
  sqlite3_vtab **ppVtab,
  char **pzErr
);

int {{table_name}}Column(
  sqlite3_vtab_cursor *cur,
  sqlite3_context *ctx,
  int col
);

int {{table_name}}Filter(
  sqlite3_vtab_cursor *pVtabCursor,
  int idxNum,
  const char *idxStr,
  int argc,
  sqlite3_value **argv
);

static sqlite3_module {{table_name}}Module = {
  0,
  {{table_name}}Create,
  {{table_name}}Create,
  xBestIndex,
  xDestroy<x_vtab<sqlite3_{{table_name}}>>,
  xDestroy<x_vtab<sqlite3_{{table_name}}>>,
  xOpen<base_cursor>,
  xClose<base_cursor>,
  {{table_name}}Filter,
  xNext<base_cursor>,
  xEof<base_cursor, x_vtab<sqlite3_{{table_name}}>>,
  {{table_name}}Column,
  xRowid<base_cursor>,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
};

}}

#endif /* OSQUERY_TABLES_{{table_name.upper()}}_H */

"""

# IMPL_TEMPLATE is the jinja template used to generate the virtual table
# implementation file
IMPL_TEMPLATE = """// Copyright 2004-present Facebook. All Rights Reserved.

/*
** This file is generated. Do not modify it manually!
*/

#include "osquery/tables/{{table_name}}.h"
#include "{{header}}"

#include <string>
#include <vector>
#include <cstring>

#include <boost/lexical_cast.hpp>

#include "osquery/tables/base.h"

namespace osquery { namespace tables {

const std::string
  sqlite3_{{table_name}}_create_table_statement =
  "CREATE TABLE {{table_name}}("
  {% for col in schema %}\
  "{{col.name}}\
 {% if col.type == "std::string" %}VARCHAR{% endif %}\
 {% if col.type == "int" %}INTEGER{% endif %}\
{% if not loop.last %}, {% endif %}"
  {% endfor %}\
  ")";

int {{table_name}}Create(
  sqlite3 *db,
  void *pAux,
  int argc,
  const char *const *argv,
  sqlite3_vtab **ppVtab,
  char **pzErr
) {
  return xCreate<
    x_vtab<sqlite3_{{table_name}}>,
    sqlite3_{{table_name}}
  >(
    db, pAux, argc, argv, ppVtab, pzErr,
    sqlite3_{{table_name}}_create_table_statement.c_str()
  );
}

int {{table_name}}Column(
  sqlite3_vtab_cursor *cur,
  sqlite3_context *ctx,
  int col
) {
  base_cursor *pCur = (base_cursor*)cur;
  x_vtab<sqlite3_{{table_name}}> *pVtab =
    (x_vtab<sqlite3_{{table_name}}>*)cur->pVtab;

  if(pCur->row >= 0 && pCur->row < pVtab->pContent->n) {
    switch (col) {
{% for col in schema %}\
      // {{ col.name }}
      case {{ loop.index0 }}:
{% if col.type == "std::string" %}\
        sqlite3_result_text(
          ctx,
          (pVtab->pContent->{{col.name}}[pCur->row]).c_str(),
          -1,
          nullptr
        );
{% endif %}\
{% if col.type == "int" %}\
        sqlite3_result_int(
          ctx,
          (int)pVtab->pContent->{{col.name}}[pCur->row]
        );
{% endif %}\
        break;
{% endfor %}\
    }
  }
  return SQLITE_OK;
}

int {{table_name}}Filter(
  sqlite3_vtab_cursor *pVtabCursor,
  int idxNum,
  const char *idxStr,
  int argc,
  sqlite3_value **argv
) {
  base_cursor *pCur = (base_cursor *)pVtabCursor;
  x_vtab<sqlite3_{{table_name}}> *pVtab =
    (x_vtab<sqlite3_{{table_name}}>*)pVtabCursor->pVtab;

  pCur->row = 0;
{% for col in schema %}\
  pVtab->pContent->{{col.name}} = {};
{% endfor %}\

  for (auto& row : osquery::tables::{{function}}()) {
{% for col in schema %}\
{% if col.type == "std::string" %}\
    pVtab->pContent->{{col.name}}.push_back(row["{{col.name}}"]);
{% endif %}\
{% if col.type == "int" %}\
    pVtab->pContent->{{col.name}}\
.push_back(boost::lexical_cast<int>(row["{{col.name}}"]));
{% endif %}\
{% endfor %}\
  }

  pVtab->pContent->n = pVtab->pContent->{{schema[0].name}}.size();

  return SQLITE_OK;
}

}}

"""

def usage():
    """print program usage"""
    print("Usage: %s <filename>" % sys.argv[0])

class Singleton(object):
    """
    Make sure that anything that subclasses Singleton can only be instantiated
    once
    """

    _instance = None

    def __new__(self, *args, **kwargs):
        if not self._instance:
            self._instance = super(Singleton, self).__new__(
                self, *args, **kwargs)
        return self._instance

class TableState(Singleton):
    """
    Maintain the state of of the table commands during the execution of
    the config file
    """

    def __init__(self):
        self.table_name = ""
        self.schema = []
        self.header = ""
        self.impl = ""
        self.function = ""

    def generate(self):
        """Generate the virtual table files"""
        logging.debug("TableState.generate")
        self.header_content = jinja2.Template(HEADER_TEMPLATE).render(
            table_name=self.table_name,
            schema=self.schema,
        )
        self.impl_content = jinja2.Template(IMPL_TEMPLATE).render(
            table_name=self.table_name,
            schema=self.schema,
            header=self.header,
            impl=self.impl,
            function=self.function,
        )

        base = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        self.header_path = os.path.join(
            base,
            "osquery/tables/%s.h" % self.table_name
        )
        self.impl_path = os.path.join(
            base,
            "osquery/tables/generated/%s.cpp" % self.table_name
        )

        logging.info("generating %s" % self.header_path)
        with open(self.header_path, "w") as file_h:
            file_h.write(self.header_content)
        logging.info("generating %s" % self.impl_path)
        with open(self.impl_path, "w") as file_h:
            file_h.write(self.impl_content)

table = TableState()

class Column(object):
    """
    A Column object to get around that fact that list literals in Python are
    ordered but dictionaries aren't
    """
    def __init__(self, **kwargs):
        self.name = kwargs.get("name", "")
        self.type = kwargs.get("type", "")

def table_name(name):
    """define the virtual table name"""
    logging.debug("- table_name")
    logging.debug("  - called with: %s" % name)
    table.table_name = name

def schema(schema_list):
    """
    define a list of Column object which represent the columns of your virtual
    table
    """
    logging.debug("- schema")
    for col in schema_list:
        logging.debug("  - %s (%s)" % (col.name, col.type))
    table.schema = schema_list

def implementation(impl_string):
    """
    define the path to the implementation file and the function which
    implements the virtual table. You should use the following format:

      # the path is "osquery/table/implementations/foo.cpp"
      # the function is "QueryData genFoo();"
      implementation("osquery/table/implementations/foo@genFoo")
    """
    logging.debug("- implementation")
    path, function = impl_string.split("@")
    header = "%s.h" % path
    impl = "%s.cpp" % path
    logging.debug("  - header => %s" % header)
    logging.debug("  - impl => %s" % impl)
    logging.debug("  - function => %s" % function)
    table.header = header
    table.impl = impl
    table.function = function

def main(argv, argc):
    if DEVELOPING:
        logging.basicConfig(format=LOG_FORMAT, level=logging.DEBUG)
    else:
        logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)

    if argc < 2:
        usage()
        sys.exit(1)

    filename = argv[1]
    with open(filename, "rU") as file_handle:
        tree = ast.parse(file_handle.read())
        exec compile(tree, "<string>", "exec")
        table.generate()

if __name__ == "__main__":
    main(sys.argv, len(sys.argv))
