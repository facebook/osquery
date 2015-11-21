add_definitions(
  -DSQLITE_ENABLE_COLUMN_METADATA
  -DSQLITE_ENABLE_API_ARMOR
  # Functionality disables
  -DSQLITE_DISABLE_LFS
  -DSQLITE_DISABLE_DIRSYNC
  -DSQLITE_DISABLE_FTS3_UNICODE
  -DSQLITE_DISABLE_FTS4_DEFERRED
  -DDSQLITE_OMIT_ALTERTABLE
  -DSQLITE_OMIT_AUTHORIZATION
  -DSQLITE_OMIT_DEPRECATED
)

INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}/third-party/sqlite3")
ADD_SUBDIRECTORY("${CMAKE_SOURCE_DIR}/third-party/sqlite3")
