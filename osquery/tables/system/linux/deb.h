#define LIBDPKG_VOLATILE_API

extern "C" {
#include <dpkg/dpkg-db.h>
#include <dpkg/dpkg.h>
#include <dpkg/parsedump.h>
#include <dpkg/pkg-array.h>
}

#include <osquery/query.h>

namespace osquery {
namespace tables {

void w_revision(struct varbuf* vb,
                const struct pkginfo* pkg,
                const struct pkgbin* pkgbin,
                enum fwriteflags flags,
                const struct fieldinfo* fip);

#if !defined(DEB_CONSTS_H)
#define DEB_CONSTS_H 1

const struct fieldinfo fieldinfos[] = {
    {FIELD("Package"), f_name, w_name, 0},
    {FIELD("Installed-Size"),
     f_charfield,
     w_charfield,
     PKGIFPOFF(installedsize)},
    {FIELD("Architecture"), f_architecture, w_architecture, 0},
    {FIELD("Source"), f_charfield, w_charfield, PKGIFPOFF(source)},
    {FIELD("Version"), f_version, w_version, PKGIFPOFF(version)},
    {FIELD("Revision"), f_revision, w_revision, 0},
    {}};

const std::map<std::string, std::string> kFieldMappings = {
    {"Package", "name"},
    {"Version", "version"},
    {"Installed-Size", "size"},
    {"Architecture", "arch"},
    {"Source", "source"},
    {"Revision", "revision"}};
#endif

int pkg_sorter(const void* a, const void* b);

void dpkg_setup(struct pkg_array* packages);

void dpkg_teardown(struct pkg_array* packages);
}
}
