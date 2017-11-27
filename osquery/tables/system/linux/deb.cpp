#include <osquery/tables/system/linux/deb.h>


namespace osquery {

int pkg_sorter(const void *a, const void *b) {
  const struct pkginfo *pa = *(const struct pkginfo **)a;
  const struct pkginfo *pb = *(const struct pkginfo **)b;
  const char *arch_a = pa->installed.arch->name;
  const char *arch_b = pb->installed.arch->name;

  int res = strcmp(pa->set->name, pb->set->name);
  if (res != 0) {
    return res;
  }

  if (pa->installed.arch == pb->installed.arch) {
    return 0;
  }

  return strcmp(arch_a, arch_b);
}

void w_revision(struct varbuf *vb,
                const struct pkginfo *pkg,
                const struct pkgbin *pkgbin,
                enum fwriteflags flags,
                const struct fieldinfo *fip) {
  if (flags & fw_printheader) {
    varbuf_add_str(vb, "Revision: ");
  }
  varbuf_add_str(vb, pkgbin->version.revision);
  if (flags & fw_printheader) {
    varbuf_add_char(vb, '\n');
  }
}

void dpkg_setup(struct pkg_array *packages) {
  dpkg_set_progname("osquery");
  push_error_context();

  dpkg_db_set_dir("/var/lib/dpkg/");
  modstatdb_init();
  modstatdb_open(msdbrw_readonly);

  pkg_array_init_from_db(packages);
  pkg_array_sort(packages, pkg_sorter);
}

void dpkg_teardown(struct pkg_array *packages) {
  pkg_array_destroy(packages);

  pkg_db_reset();
  modstatdb_done();

  pop_error_context(ehflag_normaltidy);
}
}
