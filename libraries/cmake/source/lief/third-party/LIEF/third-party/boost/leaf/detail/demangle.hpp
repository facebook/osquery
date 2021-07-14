#ifndef BOOST_LEAF_DETAIL_DEMANGLE_HPP_INCLUDED
#define BOOST_LEAF_DETAIL_DEMANGLE_HPP_INCLUDED

// Copyright (c) 2018-2020 Emil Dotchevski and Reverge Studios, Inc.

// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

// core::demangle
//
// Copyright 2014 Peter Dimov
// Copyright 2014 Andrey Semashev
//
// Distributed under the Boost Software License, Version 1.0.
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt

#if defined(__clang__)
#	pragma clang system_header
#elif (__GNUC__*100+__GNUC_MINOR__>301) && !defined(BOOST_LEAF_ENABLE_WARNINGS)
#	pragma GCC system_header
#elif defined(_MSC_VER) && !defined(BOOST_LEAF_ENABLE_WARNINGS)
#	pragma warning(push,1)
#endif

#include <string>

#if !defined(_MSC_VER)
#	if defined(__has_include) && __has_include(<cxxabi.h>)
#		define BOOST_LEAF_HAS_CXXABI_H
#	endif
#endif

#if defined( BOOST_LEAF_HAS_CXXABI_H )
#	include <cxxabi.h>
// For some architectures (mips, mips64, x86, x86_64) cxxabi.h in Android NDK is implemented by gabi++ library
// (https://android.googlesource.com/platform/ndk/+/master/sources/cxx-stl/gabi++/), which does not implement
// abi::__cxa_demangle(). We detect this implementation by checking the include guard here.
#	if defined( __GABIXX_CXXABI_H__ )
#		undef BOOST_LEAF_HAS_CXXABI_H
#	else
#		include <cstdlib>
#		include <cstddef>
#	endif
#endif

namespace boost { namespace leaf {

	namespace leaf_detail
	{
		inline char const * demangle_alloc( char const * name ) noexcept;
		inline void demangle_free( char const * name ) noexcept;

		class scoped_demangled_name
		{
		private:

			char const * m_p;

		public:

			explicit scoped_demangled_name( char const * name ) noexcept :
				m_p( demangle_alloc( name ) )
			{
			}

			~scoped_demangled_name() noexcept
			{
				demangle_free( m_p );
			}

			char const * get() const noexcept
			{
				return m_p;
			}

			scoped_demangled_name( scoped_demangled_name const& ) = delete;
			scoped_demangled_name& operator= ( scoped_demangled_name const& ) = delete;
		};

#if defined( BOOST_LEAF_HAS_CXXABI_H )

		inline char const * demangle_alloc( char const * name ) noexcept
		{
			int status = 0;
			std::size_t size = 0;
			return abi::__cxa_demangle( name, NULL, &size, &status );
		}

		inline void demangle_free( char const * name ) noexcept
		{
			std::free( const_cast< char* >( name ) );
		}

		inline std::string demangle( char const * name )
		{
			scoped_demangled_name demangled_name( name );
			char const * p = demangled_name.get();
			if( !p )
				p = name;
			return p;
		}

#else

		inline char const * demangle_alloc( char const * name ) noexcept
		{
			return name;
		}

		inline void demangle_free( char const * ) noexcept
		{
		}

		inline std::string demangle( char const * name )
		{
			return name;
		}

#endif
	}

} }

#ifdef BOOST_LEAF_HAS_CXXABI_H
#	undef BOOST_LEAF_HAS_CXXABI_H
#endif

#endif
