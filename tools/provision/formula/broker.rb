require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Broker < AbstractOsqueryFormula
  desc "Broker Communication Library"
  homepage "https://github.com/bro/broker"
  url "https://github.com/bro/broker.git",
      :revision => "68a36ed81480ba935268bcaf7b6f2249d23436da"
  head "https://github.com/bro/broker.git"
  version "0.6"

  needs :cxx11

  bottle do
      root_url "https://osquery-packages.s3.amazonaws.com/bottles"
      cellar :any_skip_relocation
  end

  depends_on "caf"
  depends_on "cmake" => :build

  # Use static libcaf
  patch :DATA

  def install
    ENV.cxx11

    args = %W[
      --prefix=#{prefix}
      --disable-pybroker
      --enable-static-only
      --with-caf=#{default_prefix}
    ]

    system "./configure", *args
    system "make"
    system "make", "install"
  end

end

__END__
diff --git a/cmake/FindCAF.cmake b/cmake/FindCAF.cmake
index ea2860c..4a827c1 100644
--- a/cmake/FindCAF.cmake
+++ b/cmake/FindCAF.cmake
@@ -67,7 +67,7 @@ foreach (comp ${CAF_FIND_COMPONENTS})
       endif ()
       find_library(CAF_LIBRARY_${UPPERCOMP}
                    NAMES
-                     "caf_${comp}"
+                     "caf_${comp}_static"
                    HINTS
                      ${library_hints}
                      /usr/lib
--
2.7.4
diff --git a/cmake/FindCAF.cmake b/cmake/FindCAF.cmake
index 4a827c1..6a40879 100644
--- a/cmake/FindCAF.cmake
+++ b/cmake/FindCAF.cmake
@@ -38,7 +38,12 @@ foreach (comp ${CAF_FIND_COMPONENTS})
             NAMES
               ${HDRNAME}
             HINTS
-              ${header_hints}
+             ${header_hints}
+           NO_DEFAULT_PATH)
+  find_path(CAF_INCLUDE_DIR_${UPPERCOMP}
+            NAMES
+              ${HDRNAME}
+            HINTS
               /usr/include
               /usr/local/include
               /opt/local/include
@@ -70,6 +75,11 @@ foreach (comp ${CAF_FIND_COMPONENTS})
                      "caf_${comp}_static"
                    HINTS
                      ${library_hints}
+                    NO_DEFAULT_PATH)
+      find_library(CAF_LIBRARY_${UPPERCOMP}
+                   NAMES
+                     "caf_${comp}_static"
+                   HINTS
                      /usr/lib
                      /usr/local/lib
                      /opt/local/lib
--
2.7.4
diff --git a/CMakeLists.txt b/CMakeLists.txt
index e439cde..fa224cb 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -161,7 +161,7 @@ endif ()
 add_subdirectory(bindings)

 enable_testing()
-add_subdirectory(tests)
+#add_subdirectory(tests)

 string(TOUPPER ${CMAKE_BUILD_TYPE} BuildType)

--
2.7.4
