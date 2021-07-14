#ifndef BOOST_LEAF_COMMON_HPP_INCLUDED
#define BOOST_LEAF_COMMON_HPP_INCLUDED

// Copyright (c) 2018-2020 Emil Dotchevski and Reverge Studios, Inc.

// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#if defined(__clang__)
#	pragma clang system_header
#elif (__GNUC__*100+__GNUC_MINOR__>301) && !defined(BOOST_LEAF_ENABLE_WARNINGS)
#	pragma GCC system_header
#elif defined(_MSC_VER) && !defined(BOOST_LEAF_ENABLE_WARNINGS)
#	pragma warning(push,1)
#endif

#include <boost/leaf/detail/print.hpp>
#include <string>
#include <cerrno>
#ifdef _WIN32
#	include <Windows.h>
#	include <cstring>
#ifdef min
#	undef min
#endif
#ifdef max
#	undef max
#endif
#endif

namespace boost { namespace leaf {

	struct e_api_function { char const * value; };

	struct e_file_name { std::string value; };

	struct e_errno
	{
		int value;

		friend std::ostream & operator<<( std::ostream & os, e_errno const & err )
		{
			return os << type<e_errno>() << ": " << err.value << ", \"" << std::strerror(err.value) << '"';
		}
	};

	struct e_type_info_name { char const * value; };

	struct e_at_line { int value; };

	namespace windows
	{
		struct e_LastError
		{
			unsigned value;
		};
	}

} }

#endif
