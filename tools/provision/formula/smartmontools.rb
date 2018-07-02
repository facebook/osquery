require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Smartmontools < AbstractOsqueryFormula
  desc "SMART hard drive monitoring; Fork with smartctl exposed as a static library"
  homepage "https://www.smartmontools.org/"
  url "https://github.com/allanliu/smartmontools/archive/v0.3.1.tar.gz"
  sha256 "a7bde3039f207a88bee72ae7c89bc4442dc65fbe76fc1a9974718d1a128a1c0b"


  depends_on "automake" => :build
  depends_on "autoconf" => :build
  depends_on "libtool" => :build

  def install
    system "which", "automake"
    system "automake", "--version"
    system "./autogen.sh"

    ENV.append "CXXFLAGS", "-fPIC -s -Os"
    system "./configure", *osquery_autoconf_flags
    system "make", "install"
  end
end
