#ifndef BOOST_LEAF_DETAIL_PRINT_HPP_INCLUDED
#define BOOST_LEAF_DETAIL_PRINT_HPP_INCLUDED

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

#include <boost/leaf/detail/optional.hpp>
#include <exception>
#include <ostream>
#include <cstring>

namespace boost { namespace leaf {

	namespace leaf_detail
	{
		template <int N>
		BOOST_LEAF_CONSTEXPR inline char const * check_prefix( char const * t, char const (&prefix)[N] )
		{
			return std::strncmp(t,prefix,sizeof(prefix)-1)==0 ? t+sizeof(prefix)-1 : t;
		}
	}

	template <class Name>
	inline char const * type() noexcept
	{
		using leaf_detail::check_prefix;
	char const * t =
#ifdef __FUNCSIG__
		__FUNCSIG__;
#else
		__PRETTY_FUNCTION__;
#endif
#if defined(__clang__)
		BOOST_LEAF_ASSERT(check_prefix(t,"const char *boost::leaf::type() ")==t+32);
		return t+32;
#elif defined(__GNUC__)
		BOOST_LEAF_ASSERT(check_prefix(t,"const char* boost::leaf::type() ")==t+32);
		return t+32;
#else
		char const * clang_style = check_prefix(t,"const char *boost::leaf::type() ");
		if( clang_style!=t )
			return clang_style;
		char const * gcc_style = check_prefix(t,"const char* boost::leaf::type() ");
		if( gcc_style!=t )
			return gcc_style;
#endif
		return t;
	}

	namespace leaf_detail
	{
		template <class T, class E = void>
		struct is_printable: std::false_type
		{
		};

		template <class T>
		struct is_printable<T, decltype(std::declval<std::ostream&>()<<std::declval<T const &>(), void())>: std::true_type
		{
		};

		////////////////////////////////////////

		template <class T, class E = void>
		struct has_printable_member_value: std::false_type
		{
		};

		template <class T>
		struct has_printable_member_value<T, decltype(std::declval<std::ostream&>()<<std::declval<T const &>().value, void())>: std::true_type
		{
		};

		////////////////////////////////////////

		template <class Wrapper, bool WrapperPrintable=is_printable<Wrapper>::value, bool ValuePrintable=has_printable_member_value<Wrapper>::value>
		struct diagnostic;

		template <class Wrapper, bool ValuePrintable>
		struct diagnostic<Wrapper, true, ValuePrintable>
		{
			static constexpr bool is_invisible = false;
			static void print( std::ostream & os, Wrapper const & x )
			{
				os << x;
			}
		};

		template <class Wrapper>
		struct diagnostic<Wrapper, false, true>
		{
			static constexpr bool is_invisible = false;
			static void print( std::ostream & os, Wrapper const & x )
			{
				os << type<Wrapper>() << ": " << x.value;
			}
		};

		template <class Wrapper>
		struct diagnostic<Wrapper, false, false>
		{
			static constexpr bool is_invisible = false;
			static void print( std::ostream & os, Wrapper const & )
			{
				os << type<Wrapper>() << ": {Non-Printable}";
			}
		};

		template <>
		struct diagnostic<std::exception_ptr, false, false>
		{
			static constexpr bool is_invisible = true;
			BOOST_LEAF_CONSTEXPR static void print( std::ostream &, std::exception_ptr const & )
			{
			}
		};

		template <class T>
		void optional<T>::print( std::ostream & os, int key_to_print ) const
		{
			if( !diagnostic<T>::is_invisible )
				if( int k = key() )
				{
					if( key_to_print )
					{
						if( key_to_print!=k )
							return;
					}
					else
						os << '[' << k << ']';
					diagnostic<T>::print(os, value_);
					os << std::endl;
				}
		}
	} // leaf_detail

} }

#endif
