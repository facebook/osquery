#!/usr/bin/env python

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import re
import sys
import argparse
import platform
import subprocess

ORACLE_RELEASE = "/etc/oracle-release"
SYSTEM_RELEASE = "/etc/system-release"
LSB_RELEASE        = "/etc/lsb-release"
DEBIAN_VERSION = "/etc/debian_version"

def _platform():
    osType, _, _, _, _, _ = platform.uname()

    if osType == "Windows":
        return ("windows", "windows")
    elif osType == "Linux":
        if os.path.exists(ORACLE_RELEASE):
            return ("redhat", "oracle")

        if os.path.exists(SYSTEM_RELEASE):
            with open(SYSTEM_RELEASE, "r") as fd:
                fileContents = fd.read()

                if fileContents.find("CentOS") != -1:
                    return ("redhat", "centos")

                if fileContents.find("Red Hat Enterprise") != -1:
                    return ("redhat", "rhel")

                if fileContents.find("Amazon Linux") != -1:
                    return ("redhat", "amazon")

                if fileContents.find("Fedora") != -1:
                    return ("redhat", "fedora")

        if os.path.exists(LSB_RELEASE):
            with open(LSB_RELEASE, "r") as fd:
                fileContents = fd.read()

                if fileContents.find("DISTRIB_ID=Ubuntu") != -1:
                    return ("debian", "ubuntu")

        if os.path.exists(DEBIAN_VERSION):
            return ("debian", "debian")
    else:
        return (None, osType.lower())

def _distro(osType):
    def getRedhatDistroVersion(pattern):
        with open(SYSTEM_RELEASE, "r") as fd:
            contents = fd.read()

            result = re.findall(pattern, contents)
            if result and len(result) == 1:
                return result[0].replace("release ", osType)
        return None

    def commandOutput(cmd):
        try:
            output = subprocess.check_output(cmd)
            return output
        except subprocess.CalledProcessError:
            return None
        except WindowsError:
            return None

    _, _, osVersion, _, _, _ = platform.uname()

    if osType == "oracle":
        result = getRedhatDistroVersion(r'release [5-7]')
        if result is not None:
            return result
    elif osType in ["centos", "rhel"]:
        result = getRedhatDistroVersion(r'release [6-7]')
        if result is not None:
            return result
    elif osType == "amazon":
        result = getRedhatDistroVersion(r'release 20[12][0-9]\.[0-9][0-9]')
        if result is not None:
            return result
    elif osType == "ubuntu":
        with open(LSB_RELEASE, "r") as fd:
            contents = fd.read()
            results = re.findall(r'DISTRIB_CODENAME=(.*)', contents)
            if len(results) == 1:
                return results[0]
    elif osType == "darwin":
        rawResult = commandOutput(["sw_vers", "-productVersion"])
        if rawResult is not None:
            results = re.findall(r'[0-9]+\.[0-9]+', rawResult)
            if len(results) == 1:
                return results[0]
    elif osType == "fedora":
        with open(SYSTEM_RELEASE, "r") as fd:
          contents = fd.read()
          results = contents.split()
          if len(results) > 2:
            return results[2]
    elif osType == "debian":
        result = commandOutput(["lsb_release", "-cs"])
        if result is not None:
            return result
    elif osType == "freebsd":
        rawResult = commandOutput(["uname", "-r"])
        results = rawResult.split("-")
        if len(results) > 0:
          return results[0]
    elif osType == "windows":
        return "windows%s" % osVersion

    return "unknown_version"

def platformAction():
    family, osType = _platform()
    print(osType)

def distroAction():
    family, osType = _platform()
    print(_distro(osType))

def familyAction():
    family, osType = _platform()
    if family:
        print(family)

def defaultAction():
    family, osType = _platform()
    distro = _distro(osType)
    print("%s;%s" % (osType, distro))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Platform detection script for osquery")
    parser.add_argument("--platform", action="store_true", help="Outputs the detected platform")
    parser.add_argument("--distro", action="store_true", help="Outputs the detected distribution")
    parser.add_argument("--family", action="store_true", help="Outputs the detected family")

    args = parser.parse_args()

    if args.platform and \
        not args.distro and \
        not args.family:
      platformAction()
    elif not args.platform and \
        args.distro and \
        not args.family:
      distroAction()
    elif not args.platform and \
        not args.distro and \
        args.family:
      familyAction()
    else:
      defaultAction()

    sys.exit(0)
