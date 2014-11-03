// Copyright 2004-present Facebook. All Rights Reserved.

#include <boost/algorithm/string.hpp>

// see README.api of libdpkg-dev
#define LIBDPKG_VOLATILE_API

extern "C" {
#include <dpkg/dpkg-db.h>
// copy pasted from dpkg-db.h
// these enums are inside struct pkginfo and are not visible for other headers
enum pkgwant {
  want_unknown, want_install, want_hold, want_deinstall, want_purge,
  /** Not allowed except as special sentinel value in some places. */
  want_sentinel,
} want;
/** The error flag bitmask. */
enum pkgeflag {
  eflag_ok		= 0,
  eflag_reinstreq	= 1,
} eflag;
enum pkgstatus {
  stat_notinstalled,
  stat_configfiles,
  stat_halfinstalled,
  stat_unpacked,
  stat_halfconfigured,
  stat_triggersawaited,
  stat_triggerspending,
  stat_installed
} status;

#include <dpkg/dpkg.h>
#include <dpkg/pkg-array.h>
#include <dpkg/pkg-show.h>
#include <dpkg/parsedump.h>
#include <dpkg/varbuf.h>
}

#include "osquery/database.h"

namespace osquery {
namespace tables {

const std::map<std::string, std::string> kFieldMappings = {
    {"Package", "name"},
    {"Version", "version"},
    {"Installed-Size", "size"},
    {"Architecture", "arch"},
    {"Source", "source"},
    {"MD5sum", "md5sum"},
};

/**
 * Fields information - taken from lib/dpkg/parse.c
 */
const struct fieldinfo fieldinfos[]= {
  /* Note: Capitalization of field name strings is important. */
  { "Package",          f_name,            w_name                                     },
  { "Essential",        f_boolean,         w_booleandefno,   PKGIFPOFF(essential)     },
  { "Status",           f_status,          w_status                                   },
  { "Priority",         f_priority,        w_priority                                 },
  { "Section",          f_section,         w_section                                  },
  { "Installed-Size",   f_charfield,       w_charfield,      PKGIFPOFF(installedsize) },
  { "Origin",           f_charfield,       w_charfield,      PKGIFPOFF(origin)        },
  { "Maintainer",       f_charfield,       w_charfield,      PKGIFPOFF(maintainer)    },
  { "Bugs",             f_charfield,       w_charfield,      PKGIFPOFF(bugs)          },
  { "Architecture",     f_architecture,    w_architecture                             },
  { "Multi-Arch",       f_multiarch,       w_multiarch,      PKGIFPOFF(multiarch)     },
  { "Source",           f_charfield,       w_charfield,      PKGIFPOFF(source)        },
  { "Version",          f_version,         w_version,        PKGIFPOFF(version)       },
  { "Revision",         f_revision,        w_null                                     },
  { "Config-Version",   f_configversion,   w_configversion                            },
  { "Replaces",         f_dependency,      w_dependency,     dep_replaces             },
  { "Provides",         f_dependency,      w_dependency,     dep_provides             },
  { "Depends",          f_dependency,      w_dependency,     dep_depends              },
  { "Pre-Depends",      f_dependency,      w_dependency,     dep_predepends           },
  { "Recommends",       f_dependency,      w_dependency,     dep_recommends           },
  { "Suggests",         f_dependency,      w_dependency,     dep_suggests             },
  { "Breaks",           f_dependency,      w_dependency,     dep_breaks               },
  { "Conflicts",        f_dependency,      w_dependency,     dep_conflicts            },
  { "Enhances",         f_dependency,      w_dependency,     dep_enhances             },
  { "Conffiles",        f_conffiles,       w_conffiles                                },
  { "Filename",         f_filecharf,       w_filecharf,      FILEFOFF(name)           },
  { "Size",             f_filecharf,       w_filecharf,      FILEFOFF(size)           },
  { "MD5sum",           f_filecharf,       w_filecharf,      FILEFOFF(md5sum)         },
  { "MSDOS-Filename",   f_filecharf,       w_filecharf,      FILEFOFF(msdosname)      },
  { "Description",      f_charfield,       w_charfield,      PKGIFPOFF(description)   },
  { "Triggers-Pending", f_trigpend,        w_trigpend                                 },
  { "Triggers-Awaited", f_trigaw,          w_trigaw                                   },
  /* Note that aliases are added to the nicknames table. */
  {  NULL                                                                             }
};


Row extractDebPackageInfo(const struct pkginfo *pkg, const struct pkgbin *pkgbin) {
  Row r;
  const struct fieldinfo *fip;

  struct varbuf vb;
  varbuf_init(&vb, 20);
  for (fip= fieldinfos; fip->name; fip++) {
    fip->wcall(&vb, pkg, pkgbin, fw_printheader, fip);

    std::string line = vb.string();
    if (!line.empty()) {
      std::size_t separator_position = line.find(':');
      std::string key = line.substr(0, separator_position);
      std::string value = line.substr(separator_position+1, line.length());
      auto it = kFieldMappings.find(key);
      if (it != kFieldMappings.end()) {
        boost::algorithm::trim(value);
        r[it->second] = value;
      }
    }
    varbuf_reset(&vb);
  }
  varbuf_destroy(&vb);
  return r;
}

QueryData genDebs() {
  QueryData results;

  // init
  struct pkg_array array;
  struct pkginfo *pkg;
  int i;
  dpkg_program_init("dpkg");
  modstatdb_open(msdbrw_readonly);
  pkg_array_init_from_db(&array);
  pkg_array_sort(&array, pkg_sorter_by_nonambig_name_arch);

  for (i = 0; i < array.n_pkgs; i++) {
    pkg = array.pkgs[i];

    if (pkg->status == pkg->stat_notinstalled) {
    	continue;
    }

    results.push_back(extractDebPackageInfo(pkg, &pkg->installed));
  }

  pkg_array_destroy(&array);
  dpkg_program_done();

  return results;
}
}
}
