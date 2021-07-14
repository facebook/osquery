#ifndef BOOST_LEAF_CONFIG_HPP_INCLUDED
#define BOOST_LEAF_CONFIG_HPP_INCLUDED

// Copyright (c) 2018-2020 Emil Dotchevski and Reverge Studios, Inc.

// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

// The following is based on Boost Config.

// (C) Copyright John Maddock 2001 - 2003.
// (C) Copyright Martin Wille 2003.
// (C) Copyright Guillaume Melquiond 2003.

#if defined(__clang__)
#	pragma clang system_header
#elif (__GNUC__*100+__GNUC_MINOR__>301) && !defined(BOOST_LEAF_ENABLE_WARNINGS)
#	pragma GCC system_header
#elif defined(_MSC_VER) && !defined(BOOST_LEAF_ENABLE_WARNINGS)
#	pragma warning(push,1)
#endif

#include <cassert>

////////////////////////////////////////

// Configure BOOST_LEAF_NO_EXCEPTIONS, unless already #defined
#ifndef BOOST_LEAF_NO_EXCEPTIONS

#	if defined __clang__ && !defined(__ibmxl__)
//	Clang C++ emulates GCC, so it has to appear early.

#		if !__has_feature(cxx_exceptions)
#			define BOOST_LEAF_NO_EXCEPTIONS
#		endif

#	elif defined __DMC__
//	Digital Mars C++

#		if !defined(_CPPUNWIND)
#			define BOOST_LEAF_NO_EXCEPTIONS
#		endif

#	elif defined(__GNUC__) && !defined(__ibmxl__)
//	GNU C++:

#		if !defined(__EXCEPTIONS)
#			define BOOST_LEAF_NO_EXCEPTIONS
#		endif

#	elif defined __KCC
//	Kai C++

#		if !defined(_EXCEPTIONS)
#			define BOOST_LEAF_NO_EXCEPTIONS
#		endif

#	elif defined __CODEGEARC__
//	CodeGear - must be checked for before Borland

#		if !defined(_CPPUNWIND) && !defined(__EXCEPTIONS)
#			define BOOST_LEAF_NO_EXCEPTIONS
#		endif

#	elif defined __BORLANDC__
//	Borland

#		if !defined(_CPPUNWIND) && !defined(__EXCEPTIONS)
# 			define BOOST_LEAF_NO_EXCEPTIONS
#		endif

#	elif defined  __MWERKS__
//	Metrowerks CodeWarrior

#		if !__option(exceptions)
#			define BOOST_LEAF_NO_EXCEPTIONS
#		endif

#	elif defined(__IBMCPP__) && defined(__COMPILER_VER__) && defined(__MVS__)
//	IBM z/OS XL C/C++

#		if !defined(_CPPUNWIND) && !defined(__EXCEPTIONS)
#			define BOOST_LEAF_NO_EXCEPTIONS
#		endif

#	elif defined(__ibmxl__)
//	IBM XL C/C++ for Linux (Little Endian)

#		if !__has_feature(cxx_exceptions)
#			define BOOST_LEAF_NO_EXCEPTIONS
#		endif

#	elif defined _MSC_VER
//	Microsoft Visual C++
//
//	Must remain the last #elif since some other vendors (Metrowerks, for
//	example) also #define _MSC_VER

#		if !defined(_CPPUNWIND)
#			define BOOST_LEAF_NO_EXCEPTIONS
#		endif
#	endif

#endif

////////////////////////////////////////

#ifndef BOOST_LEAF_DIAGNOSTICS
#	define BOOST_LEAF_DIAGNOSTICS 1
#endif

#if BOOST_LEAF_DIAGNOSTICS!=0 && BOOST_LEAF_DIAGNOSTICS!=1
#	error BOOST_LEAF_DIAGNOSTICS must be 0 or 1.
#endif

////////////////////////////////////////

#ifdef _MSC_VER
#	define BOOST_LEAF_ALWAYS_INLINE __forceinline
#else
#	define BOOST_LEAF_ALWAYS_INLINE __attribute__((always_inline)) inline
#endif

////////////////////////////////////////

#ifndef BOOST_LEAF_NODISCARD
#	if __cplusplus >= 201703L
#		define BOOST_LEAF_NODISCARD [[nodiscard]]
#	else
#		define BOOST_LEAF_NODISCARD
#	endif
#endif

////////////////////////////////////////

#ifndef BOOST_LEAF_CONSTEXPR
#	if __cplusplus > 201402L
#		define BOOST_LEAF_CONSTEXPR constexpr
#		define BOOST_LEAF_STD_UNCAUGHT_EXCEPTIONS 1
#	else
#		define BOOST_LEAF_CONSTEXPR
#		define BOOST_LEAF_STD_UNCAUGHT_EXCEPTIONS 0
#	endif
#endif

////////////////////////////////////////

#ifndef BOOST_LEAF_ASSERT
#	ifdef BOOST_ASSERT
#		define BOOST_LEAF_ASSERT BOOST_ASSERT
#	else
#		define BOOST_LEAF_ASSERT assert
#	endif
#endif

#endif
