require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Yara < AbstractOsqueryFormula
  desc "Malware identification and classification tool"
  homepage "https://github.com/VirusTotal/yara/"
  head "https://github.com/VirusTotal/yara.git"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "b4a5d705c44300b204deecc8948547edd9338085c5f243423ff3bbd5e429c75a" => :el_capitan
    sha256 "24715c9087cb6d700ef2ff87127a6d4eb09bfecbf87d4b94f7f050b16c441f9b" => :x86_64_linux
  end

  stable do
    url "https://github.com/VirusTotal/yara/archive/v3.5.0.tar.gz"
    sha256 "4bc72ee755db85747f7e856afb0e817b788a280ab5e73dee42f159171a9b5299"

    patch do
      url "https://github.com/VirusTotal/yara/pull/529.diff"
      sha256 "7d865ebbb1f31a5b5e0337001842d5aab42b2b9683b307c187425fb76dc9524f"
    end
  end

  depends_on "libtool" => :build
  depends_on "autoconf" => :build
  depends_on "automake" => :build

  depends_on "pcre"
  depends_on "openssl"

  def install
    ENV.cxx11

    # Use of "inline" requires gnu89 semantics
    ENV.append "CFLAGS", "-std=gnu89" if ENV.compiler == :clang

    # find Homebrew's libpcre
    ENV.append "LDFLAGS", "-L#{Formula["pcre"].opt_lib} -lpcre"

    system "./bootstrap.sh"
    system "./configure", "--disable-silent-rules",
                          "--disable-dependency-tracking",
                          "--prefix=#{prefix}"
    system "make", "install"
  end
end
