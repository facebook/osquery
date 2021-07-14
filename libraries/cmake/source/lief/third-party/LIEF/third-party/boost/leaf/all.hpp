#ifndef BOOST_LEAF_ALL_HPP_INCLUDED
#define BOOST_LEAF_ALL_HPP_INCLUDED

// Copyright (c) 2018-2020 Emil Dotchevski and Reverge Studios, Inc.

// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

// >>> #include <boost/leaf/config.hpp>
#line 1 "boost/leaf/config.hpp"
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
// <<< #include <boost/leaf/config.hpp>
#line 10 "../../include/boost/leaf/detail/all.hpp"
// >>> #include <boost/leaf/capture.hpp>
#line 1 "boost/leaf/capture.hpp"
#ifndef BOOST_LEAF_CAPTURE_HPP_INCLUDED
#define BOOST_LEAF_CAPTURE_HPP_INCLUDED

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

// >>> #include <boost/leaf/exception.hpp>
#line 1 "boost/leaf/exception.hpp"
#ifndef BOOST_LEAF_EXCEPTION_HPP_INCLUDED
#define BOOST_LEAF_EXCEPTION_HPP_INCLUDED

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

// >>> #include <boost/leaf/error.hpp>
#line 1 "boost/leaf/error.hpp"
#ifndef BOOST_LEAF_ERROR_HPP_INCLUDED
#define BOOST_LEAF_ERROR_HPP_INCLUDED

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

// >>> #include <boost/leaf/detail/function_traits.hpp>
#line 1 "boost/leaf/detail/function_traits.hpp"
#ifndef BOOST_LEAF_DETAIL_FUNCTION_TRAITS_HPP_INCLUDED
#define BOOST_LEAF_DETAIL_FUNCTION_TRAITS_HPP_INCLUDED

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

// >>> #include <boost/leaf/detail/mp11.hpp>
#line 1 "boost/leaf/detail/mp11.hpp"
#ifndef BOOST_LEAF_DETAIL_MP11_HPP_INCLUDED
#define BOOST_LEAF_DETAIL_MP11_HPP_INCLUDED

//  Copyright 2015-2017 Peter Dimov.
//  Copyright 2019 Emil Dotchevski.
//
//  Distributed under the Boost Software License, Version 1.0.
//
//  See accompanying file LICENSE_1_0.txt or copy at
//  http://www.boost.org/LICENSE_1_0.txt

// LEAF needs a few mp11 utilities, which have been copied into the internal
// namespace boost::leaf::leaf_detail_mp11 in order to avoid a dependency on
// the entire mp11 library. The BOOST_LEAF_USE_BOOST_MP11 configuration macro
// tells LEAF to not bother and just use <boost/mp11/algorithm.hpp> instead.
#ifdef BOOST_LEAF_USE_BOOST_MP11

#include <boost/mp11/algorithm.hpp>

namespace boost { namespace leaf { namespace leaf_detail_mp11 = ::boost::mp11; } }

#else

#include <type_traits>
#include <cstddef>

namespace boost { namespace leaf { namespace leaf_detail_mp11 {

// mp_list<T...>
template<class... T> struct mp_list
{
};

// mp_identity
template<class T> struct mp_identity
{
    using type = T;
};

// mp_inherit
template<class... T> struct mp_inherit: T... {};

// mp_if, mp_if_c
namespace detail
{

template<bool C, class T, class... E> struct mp_if_c_impl
{
};

template<class T, class... E> struct mp_if_c_impl<true, T, E...>
{
    using type = T;
};

template<class T, class E> struct mp_if_c_impl<false, T, E>
{
    using type = E;
};

} // namespace detail

template<bool C, class T, class... E> using mp_if_c = typename detail::mp_if_c_impl<C, T, E...>::type;
template<class C, class T, class... E> using mp_if = typename detail::mp_if_c_impl<static_cast<bool>(C::value), T, E...>::type;

// mp_bool
template<bool B> using mp_bool = std::integral_constant<bool, B>;

using mp_true = mp_bool<true>;
using mp_false = mp_bool<false>;

// mp_to_bool
template<class T> using mp_to_bool = mp_bool<static_cast<bool>( T::value )>;

// mp_not<T>
template<class T> using mp_not = mp_bool< !T::value >;

// mp_int
template<int I> using mp_int = std::integral_constant<int, I>;

// mp_size_t
template<std::size_t N> using mp_size_t = std::integral_constant<std::size_t, N>;

// mp_set_contains<S, V>
namespace detail
{

template<class S, class V> struct mp_set_contains_impl;

template<template<class...> class L, class... T, class V> struct mp_set_contains_impl<L<T...>, V>
{
    using type = mp_to_bool<std::is_base_of<mp_identity<V>, mp_inherit<mp_identity<T>...> > >;
};

} // namespace detail

template<class S, class V> using mp_set_contains = typename detail::mp_set_contains_impl<S, V>::type;

// mp_set_push_back<S, T...>
namespace detail
{

template<class S, class... T> struct mp_set_push_back_impl;

template<template<class...> class L, class... U> struct mp_set_push_back_impl<L<U...>>
{
    using type = L<U...>;
};

template<template<class...> class L, class... U, class T1, class... T> struct mp_set_push_back_impl<L<U...>, T1, T...>
{
    using S = mp_if<mp_set_contains<L<U...>, T1>, L<U...>, L<U..., T1>>;
    using type = typename mp_set_push_back_impl<S, T...>::type;
};

} // namespace detail

template<class S, class... T> using mp_set_push_back = typename detail::mp_set_push_back_impl<S, T...>::type;

// mp_unique<L>
namespace detail
{

template<class L> struct mp_unique_impl;

template<template<class...> class L, class... T> struct mp_unique_impl<L<T...>>
{
    using type = mp_set_push_back<L<>, T...>;
};

} // namespace detail

template<class L> using mp_unique = typename detail::mp_unique_impl<L>::type;

// mp_append<L...>

namespace detail
{

template<class... L> struct mp_append_impl;

template<> struct mp_append_impl<>
{
    using type = mp_list<>;
};

template<template<class...> class L, class... T> struct mp_append_impl<L<T...>>
{
    using type = L<T...>;
};

template<template<class...> class L1, class... T1, template<class...> class L2, class... T2, class... Lr> struct mp_append_impl<L1<T1...>, L2<T2...>, Lr...>
{
    using type = typename mp_append_impl<L1<T1..., T2...>, Lr...>::type;
};

}

template<class... L> using mp_append = typename detail::mp_append_impl<L...>::type;

// mp_front<L>
namespace detail
{

template<class L> struct mp_front_impl
{
// An error "no type named 'type'" here means that the argument to mp_front
// is either not a list, or is an empty list
};

template<template<class...> class L, class T1, class... T> struct mp_front_impl<L<T1, T...>>
{
    using type = T1;
};

} // namespace detail

template<class L> using mp_front = typename detail::mp_front_impl<L>::type;

// mp_pop_front<L>
namespace detail
{

template<class L> struct mp_pop_front_impl
{
// An error "no type named 'type'" here means that the argument to mp_pop_front
// is either not a list, or is an empty list
};

template<template<class...> class L, class T1, class... T> struct mp_pop_front_impl<L<T1, T...>>
{
    using type = L<T...>;
};

} // namespace detail

template<class L> using mp_pop_front = typename detail::mp_pop_front_impl<L>::type;

// mp_first<L>
template<class L> using mp_first = mp_front<L>;

// mp_rest<L>
template<class L> using mp_rest = mp_pop_front<L>;

// mp_remove_if<L, P>
namespace detail
{

template<class L, template<class...> class P> struct mp_remove_if_impl;

template<template<class...> class L, class... T, template<class...> class P> struct mp_remove_if_impl<L<T...>, P>
{
    template<class U> using _f = mp_if<P<U>, mp_list<>, mp_list<U>>;
    using type = mp_append<L<>, _f<T>...>;
};

} // namespace detail

template<class L, template<class...> class P> using mp_remove_if = typename detail::mp_remove_if_impl<L, P>::type;

// integer_sequence
template<class T, T... I> struct integer_sequence
{
};

// detail::make_integer_sequence_impl
namespace detail
{

// iseq_if_c
template<bool C, class T, class E> struct iseq_if_c_impl;

template<class T, class E> struct iseq_if_c_impl<true, T, E>
{
    using type = T;
};

template<class T, class E> struct iseq_if_c_impl<false, T, E>
{
    using type = E;
};

template<bool C, class T, class E> using iseq_if_c = typename iseq_if_c_impl<C, T, E>::type;

// iseq_identity
template<class T> struct iseq_identity
{
    using type = T;
};

template<class S1, class S2> struct append_integer_sequence;

template<class T, T... I, T... J> struct append_integer_sequence<integer_sequence<T, I...>, integer_sequence<T, J...>>
{
    using type = integer_sequence< T, I..., ( J + sizeof...(I) )... >;
};

template<class T, T N> struct make_integer_sequence_impl;

template<class T, T N> struct make_integer_sequence_impl_
{
private:

    static_assert( N >= 0, "make_integer_sequence<T, N>: N must not be negative" );

    static T const M = N / 2;
    static T const R = N % 2;

    using S1 = typename make_integer_sequence_impl<T, M>::type;
    using S2 = typename append_integer_sequence<S1, S1>::type;
    using S3 = typename make_integer_sequence_impl<T, R>::type;
    using S4 = typename append_integer_sequence<S2, S3>::type;

public:

    using type = S4;
};

template<class T, T N> struct make_integer_sequence_impl: iseq_if_c<N == 0, iseq_identity<integer_sequence<T>>, iseq_if_c<N == 1, iseq_identity<integer_sequence<T, 0>>, make_integer_sequence_impl_<T, N> > >
{
};

} // namespace detail

// make_integer_sequence
template<class T, T N> using make_integer_sequence = typename detail::make_integer_sequence_impl<T, N>::type;

// index_sequence
template<std::size_t... I> using index_sequence = integer_sequence<std::size_t, I...>;

// make_index_sequence
template<std::size_t N> using make_index_sequence = make_integer_sequence<std::size_t, N>;

// index_sequence_for
template<class... T> using index_sequence_for = make_integer_sequence<std::size_t, sizeof...(T)>;

// implementation by Bruno Dutra (by the name is_evaluable)
namespace detail
{

template<template<class...> class F, class... T> struct mp_valid_impl
{
    template<template<class...> class G, class = G<T...>> static mp_true check(int);
    template<template<class...> class> static mp_false check(...);

    using type = decltype(check<F>(0));
};

} // namespace detail

template<template<class...> class F, class... T> using mp_valid = typename detail::mp_valid_impl<F, T...>::type;

} } }

#endif

#endif
// <<< #include <boost/leaf/detail/mp11.hpp>
#line 18 "boost/leaf/detail/function_traits.hpp"
#include <tuple>

namespace boost { namespace leaf {

	namespace leaf_detail
	{
		template<class...>
		struct gcc49_workaround //Thanks Glen Fernandes
		{
			typedef void type;
		};

		template<class... T>
		using void_t = typename gcc49_workaround<T...>::type;

		template<class F,class V=void>
		struct function_traits
		{
			constexpr static int arity = -1;
		};

		template<class F>
		struct function_traits<F, void_t<decltype(&F::operator())>>
		{
		private:

			using tr = function_traits<decltype(&F::operator())>;

		public:

			using return_type = typename tr::return_type;
			static constexpr int arity = tr::arity - 1;

			using mp_args = typename leaf_detail_mp11::mp_rest<typename tr::mp_args>;

			template <int I>
			struct arg:
				tr::template arg<I+1>
			{
			};
		};

		template<class R, class... A>
		struct function_traits<R(A...)>
		{
			using return_type = R;
			static constexpr int arity = sizeof...(A);

			using mp_args = leaf_detail_mp11::mp_list<A...>;

			template <int I>
			struct arg
			{
				static_assert(I < arity, "I out of range");
				using type = typename std::tuple_element<I,std::tuple<A...>>::type;
			};
		};

		template<class F> struct function_traits<F&> : function_traits<F> { };
		template<class F> struct function_traits<F&&> : function_traits<F> { };
		template<class R, class... A> struct function_traits<R(*)(A...)> : function_traits<R(A...)> { };
		template<class R, class... A> struct function_traits<R(* &)(A...)> : function_traits<R(A...)> { };
		template<class R, class... A> struct function_traits<R(* const &)(A...)> : function_traits<R(A...)> { };
		template<class C, class R, class... A> struct function_traits<R(C::*)(A...)> : function_traits<R(C&,A...)> { };
		template<class C, class R, class... A> struct function_traits<R(C::*)(A...) const> : function_traits<R(C const &,A...)> { };
		template<class C, class R> struct function_traits<R(C::*)> : function_traits<R(C&)> { };

		template <class F>
		using fn_return_type = typename function_traits<F>::return_type;

		template <class F, int I>
		using fn_arg_type = typename function_traits<F>::template arg<I>::type;

		template <class F>
		using fn_mp_args = typename function_traits<F>::mp_args;
	} // namespace leaf_detail

} }

#endif
// <<< #include <boost/leaf/detail/function_traits.hpp>
#line 18 "boost/leaf/error.hpp"
// >>> #include <boost/leaf/detail/print.hpp>
#line 1 "boost/leaf/detail/print.hpp"
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

// >>> #include <boost/leaf/detail/optional.hpp>
#line 1 "boost/leaf/detail/optional.hpp"
#ifndef BOOST_LEAF_DETAIL_OPTIONAL_HPP_INCLUDED
#define BOOST_LEAF_DETAIL_OPTIONAL_HPP_INCLUDED

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

#include <utility>
#include <new>
#include <ostream>

namespace boost { namespace leaf {

	namespace leaf_detail
	{
		template <class T>
		class optional
		{
			int key_;
			union { T value_; };

		public:

			typedef T value_type;

			BOOST_LEAF_CONSTEXPR optional() noexcept:
				key_(0)
			{
			}

			BOOST_LEAF_CONSTEXPR optional( optional const & x ):
				key_(x.key_)
			{
				if( x.key_ )
					(void) new (&value_) T( x.value_ );
			}

			BOOST_LEAF_CONSTEXPR optional( optional && x ) noexcept:
				key_(x.key_)
			{
				if( x.key_ )
				{
					(void) new (&value_) T( std::move(x.value_) );
					x.reset();
				}
			}

			BOOST_LEAF_CONSTEXPR optional( int key, T const & v ):
				key_(key),
				value_(v)
			{
				BOOST_LEAF_ASSERT(!empty());
			}

			BOOST_LEAF_CONSTEXPR optional( int key, T && v ) noexcept:
				key_(key),
				value_(std::move(v))
			{
				BOOST_LEAF_ASSERT(!empty());
			}

			BOOST_LEAF_CONSTEXPR optional & operator=( optional const & x )
			{
				reset();
				if( int key = x.key() )
				{
					put(key, x.value_);
					key_ = key;
				}
				return *this;
			}

			BOOST_LEAF_CONSTEXPR optional & operator=( optional && x ) noexcept
			{
				reset();
				if( int key = x.key() )
				{
					put(key, std::move(x.value_));
					x.reset();
				}
				return *this;
			}

			~optional() noexcept
			{
				reset();
			}

			BOOST_LEAF_CONSTEXPR bool empty() const noexcept
			{
				return key_==0;
			}

			BOOST_LEAF_CONSTEXPR int key() const noexcept
			{
				return key_;
			}

			BOOST_LEAF_CONSTEXPR void set_key( int key ) noexcept
			{
				BOOST_LEAF_ASSERT(!empty());
				key_ = key;
			}

			BOOST_LEAF_CONSTEXPR void reset() noexcept
			{
				if( key_ )
				{
					value_.~T();
					key_=0;
				}
			}

			BOOST_LEAF_CONSTEXPR T & put( int key, T const & v )
			{
				BOOST_LEAF_ASSERT(key);
				reset();
				(void) new(&value_) T(v);
				key_=key;
				return value_;
			}

			BOOST_LEAF_CONSTEXPR T & put( int key, T && v ) noexcept
			{
				BOOST_LEAF_ASSERT(key);
				reset();
				(void) new(&value_) T(std::move(v));
				key_=key;
				return value_;
			}

			BOOST_LEAF_CONSTEXPR T const * has_value(int key) const noexcept
			{
				BOOST_LEAF_ASSERT(key);
				return key_==key ? &value_ : 0;
			}

			BOOST_LEAF_CONSTEXPR T * has_value(int key) noexcept
			{
				BOOST_LEAF_ASSERT(key);
				return key_==key ? &value_ : 0;
			}

			BOOST_LEAF_CONSTEXPR T const & value(int key) const & noexcept
			{
				BOOST_LEAF_ASSERT(has_value(key)!=0);
				return value_;
			}

			BOOST_LEAF_CONSTEXPR T & value(int key) & noexcept
			{
				BOOST_LEAF_ASSERT(has_value(key)!=0);
				return value_;
			}

			BOOST_LEAF_CONSTEXPR T const && value(int key) const && noexcept
			{
				BOOST_LEAF_ASSERT(has_value(key)!=0);
				return value_;
			}

			BOOST_LEAF_CONSTEXPR T value(int key) && noexcept
			{
				BOOST_LEAF_ASSERT(has_value(key)!=0);
				T tmp(std::move(value_));
				reset();
				return tmp;
			}

			void print( std::ostream &, int key_to_print ) const;
		};

	} // leaf_detail

} }

#endif
// <<< #include <boost/leaf/detail/optional.hpp>
#line 18 "boost/leaf/detail/print.hpp"
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
// <<< #include <boost/leaf/detail/print.hpp>
#line 19 "boost/leaf/error.hpp"
#include <system_error>
#include <type_traits>
#include <sstream>
#include <memory>
#include <set>

#ifdef BOOST_LEAF_NO_THREADS
#	define BOOST_LEAF_THREAD_LOCAL
	namespace boost { namespace leaf {
		namespace leaf_detail
		{
			using atomic_unsigned_int = unsigned int;
		}
	} }
#else
#	include <atomic>
#	include <thread>
#	define BOOST_LEAF_THREAD_LOCAL thread_local
	namespace boost { namespace leaf {
		namespace leaf_detail
		{
			using atomic_unsigned_int = std::atomic<unsigned int>;
		}
	} }
#endif

#define BOOST_LEAF_NEW_ERROR ::leaf::leaf_detail::inject_loc{__FILE__,__LINE__,__FUNCTION__}+::boost::leaf::new_error

#define BOOST_LEAF_AUTO(v,r)\
	static_assert(::boost::leaf::is_result_type<typename std::decay<decltype(r)>::type>::value, "BOOST_LEAF_AUTO requires a result type");\
	auto && _r_##v = r;\
	if( !_r_##v )\
		return _r_##v.error();\
	auto && v = _r_##v.value()

#define BOOST_LEAF_CHECK(r)\
	{\
		static_assert(::boost::leaf::is_result_type<typename std::decay<decltype(r)>::type>::value, "BOOST_LEAF_CHECK requires a result type");\
		auto && _r = r;\
		if( !_r )\
			return _r.error();\
	}

////////////////////////////////////////

namespace boost { namespace leaf {

	namespace leaf_detail
	{
		struct inject_loc
		{
			char const * const file;
			int const line;
			char const * const fn;

			template <class T>
			friend T operator+( inject_loc loc, T && x ) noexcept
			{
				x.load_source_location_(loc.file, loc.line, loc.fn);
				return x;
			}
		};
	}

} }

////////////////////////////////////////

namespace boost { namespace leaf {

	struct e_source_location
	{
		char const * const file;
		int const line;
		char const * const function;

		friend std::ostream & operator<<( std::ostream & os, e_source_location const & x )
		{
			return os << leaf::type<e_source_location>() << ": " << x.file << '(' << x.line << ") in function " << x.function;
		}
	};

	////////////////////////////////////////

#if BOOST_LEAF_DIAGNOSTICS

	namespace leaf_detail
	{
		class e_unexpected_count
		{
		public:

			char const * (*first_type)();
			int count;

			BOOST_LEAF_CONSTEXPR explicit e_unexpected_count( char const * (*first_type)() ) noexcept:
				first_type(first_type),
				count(1)
			{
			}

			void print( std::ostream & os ) const
			{
				BOOST_LEAF_ASSERT(first_type!=0);
				BOOST_LEAF_ASSERT(count>0);
				os << "Detected ";
				if( count==1 )
					os << "1 attempt to communicate an unexpected error object";
				else
					os << count << " attempts to communicate unexpected error objects, the first one";
				os << " of type " << first_type() << std::endl;
			}
		};

		template <>
		struct diagnostic<e_unexpected_count,false,false>
		{
			static constexpr bool is_invisible = true;
			BOOST_LEAF_CONSTEXPR static void print( std::ostream &, e_unexpected_count const & ) noexcept
			{
			}
		};

		class e_unexpected_info
		{
			std::string s_;
			std::set<char const *(*)()> already_;

		public:

			e_unexpected_info() noexcept
			{
			}

			void reset() noexcept
			{
				s_.clear();
				already_.clear();
			}

			template <class E>
			void add( E const & e )
			{
				std::stringstream s;
				if( !leaf_detail::diagnostic<E>::is_invisible )
				{
					leaf_detail::diagnostic<E>::print(s,e);
					if( already_.insert(&type<E>).second  )
					{
						s << std::endl;
						s_ += s.str();
					}
				}
			}

			void print( std::ostream & os ) const
			{
				os << "Unexpected error objects:\n" << s_;
			}
		};

		template <>
		struct diagnostic<e_unexpected_info,false,false>
		{
			static constexpr bool is_invisible = true;
			BOOST_LEAF_CONSTEXPR static void print( std::ostream &, e_unexpected_info const & ) noexcept
			{
			}
		};

		inline int & tl_unexpected_enabled_counter() noexcept
		{
			static BOOST_LEAF_THREAD_LOCAL int c;
			return c;
		}
	}

#endif

	////////////////////////////////////////

	namespace leaf_detail
	{
		template <class E>
		class slot;

		template <class E>
		inline slot<E> * & tl_slot_ptr() noexcept
		{
			static BOOST_LEAF_THREAD_LOCAL slot<E> * s;
			return s;
		}

		template <class E>
		class slot:
			optional<E>
		{
			slot( slot const & ) = delete;
			slot & operator=( slot const & ) = delete;

			typedef optional<E> impl;
			slot<E> * * top_;
			slot<E> * prev_;

		public:

			BOOST_LEAF_CONSTEXPR slot() noexcept:
				top_(0)
			{
			}

			BOOST_LEAF_CONSTEXPR slot( slot && x ) noexcept:
				optional<E>(std::move(x)),
				top_(0)
			{
				BOOST_LEAF_ASSERT(x.top_==0);
			}

			BOOST_LEAF_CONSTEXPR void activate() noexcept
			{
				BOOST_LEAF_ASSERT(top_==0 || *top_!=this);
				top_ = &tl_slot_ptr<E>();
				prev_ = *top_;
				*top_ = this;
			}

			BOOST_LEAF_CONSTEXPR void deactivate() noexcept
			{
				BOOST_LEAF_ASSERT(top_!=0 && *top_==this);
				*top_ = prev_;
			}

			BOOST_LEAF_CONSTEXPR void propagate() noexcept;

			using impl::put;
			using impl::has_value;
			using impl::value;
			using impl::print;
		};

#if BOOST_LEAF_DIAGNOSTICS

		template <class E>
		BOOST_LEAF_CONSTEXPR inline void load_unexpected_count( int err_id ) noexcept
		{
			if( slot<e_unexpected_count> * sl = tl_slot_ptr<e_unexpected_count>() )
				if( e_unexpected_count * unx = sl->has_value(err_id) )
					++unx->count;
				else
					sl->put(err_id, e_unexpected_count(&type<E>));
		}

		template <class E>
		BOOST_LEAF_CONSTEXPR inline void load_unexpected_info( int err_id, E && e ) noexcept
		{
			if( slot<e_unexpected_info> * sl = tl_slot_ptr<e_unexpected_info>() )
				if( e_unexpected_info * unx = sl->has_value(err_id) )
					unx->add(e);
				else
					sl->put(err_id, e_unexpected_info()).add(e);
		}

		template <class E>
		BOOST_LEAF_CONSTEXPR inline void load_unexpected( int err_id, E && e  ) noexcept
		{
			load_unexpected_count<E>(err_id);
			load_unexpected_info(err_id, std::move(e));
		}

#endif

		template <class E>
		BOOST_LEAF_CONSTEXPR inline void slot<E>::propagate() noexcept
		{
			BOOST_LEAF_ASSERT(top_!=0 && (*top_==prev_ || *top_==this));
			if( prev_ )
			{
				impl & that_ = *prev_;
				if( that_.empty() )
				{
					impl & this_ = *this;
					that_ = std::move(this_);
				}
			}
#if BOOST_LEAF_DIAGNOSTICS
			else
			{
				int c = tl_unexpected_enabled_counter();
				BOOST_LEAF_ASSERT(c>=0);
				if( c )
					if( int err_id = impl::key() )
						load_unexpected(err_id, std::move(*this).value(err_id));
			}
#endif
		}

		template <class E>
		BOOST_LEAF_CONSTEXPR inline int load_slot( int err_id, E && e ) noexcept
		{
			static_assert(!std::is_pointer<E>::value, "Error objects of pointer types are not supported");
			using T = typename std::decay<E>::type;
			BOOST_LEAF_ASSERT((err_id&3)==1);
			if( slot<T> * p = tl_slot_ptr<T>() )
				(void) p->put(err_id, std::forward<E>(e));
#if BOOST_LEAF_DIAGNOSTICS
			else
			{
				int c = tl_unexpected_enabled_counter();
				BOOST_LEAF_ASSERT(c>=0);
				if( c )
					load_unexpected(err_id, std::forward<E>(e));
			}
#endif
			return 0;
		}

		template <class F>
		BOOST_LEAF_CONSTEXPR inline int accumulate_slot( int err_id, F && f ) noexcept
		{
			static_assert(function_traits<F>::arity==1, "Lambdas passed to accumulate must take a single e-type argument by reference");
			using E = typename std::decay<fn_arg_type<F,0>>::type;
			static_assert(!std::is_pointer<E>::value, "Error objects of pointer types are not supported");
			BOOST_LEAF_ASSERT((err_id&3)==1);
			if( auto sl = tl_slot_ptr<E>() )
				if( auto v = sl->has_value(err_id) )
					(void) std::forward<F>(f)(*v);
				else
					(void) std::forward<F>(f)(sl->put(err_id,E()));
			return 0;
		}
	} // leaf_detail

	////////////////////////////////////////

	namespace leaf_detail
	{
		template <class=void>
		struct id_factory
		{
			static atomic_unsigned_int counter;
			static BOOST_LEAF_THREAD_LOCAL unsigned current_id;

			BOOST_LEAF_CONSTEXPR static unsigned generate_next_id() noexcept
			{
				auto id = (counter+=4);
				BOOST_LEAF_ASSERT((id&3)==1);
				return id;
			}
		};

		template <class T>
		atomic_unsigned_int id_factory<T>::counter(-3);

		template <class T>
		BOOST_LEAF_THREAD_LOCAL unsigned id_factory<T>::current_id(0);

		inline int current_id() noexcept
		{
			auto id = id_factory<>::current_id;
			BOOST_LEAF_ASSERT(id==0 || (id&3)==1);
			return id;
		}

		inline int new_id() noexcept
		{
			auto id = id_factory<>::generate_next_id();
			return id_factory<>::current_id = id;
		}
	}

	////////////////////////////////////////

	namespace leaf_detail
	{
		template <class T, int Arity = function_traits<T>::arity>
		struct load_item
		{
			static_assert(Arity==0 || Arity==1, "If a functions is passed to new_error or load, it must take zero or one argument");
		};

		template <class E>
		struct load_item<E, -1>
		{
			BOOST_LEAF_CONSTEXPR static int load( int err_id, E && e ) noexcept
			{
				return load_slot(err_id, std::forward<E>(e));
			}
		};

		template <class F>
		struct load_item<F, 0>
		{
			BOOST_LEAF_CONSTEXPR static int load( int err_id, F && f ) noexcept
			{
				return load_slot(err_id, std::forward<F>(f)());
			}
		};

		template <class F>
		struct load_item<F, 1>
		{
			BOOST_LEAF_CONSTEXPR static int load( int err_id, F && f ) noexcept
			{
				return accumulate_slot(err_id, std::forward<F>(f));
			}
		};
	}

	////////////////////////////////////////

	namespace leaf_detail
	{
		class leaf_category: public std::error_category
		{
			bool equivalent( int,  std::error_condition const & ) const noexcept final override { return false; }
			bool equivalent( std::error_code const &, int ) const noexcept final override { return false; }
			char const * name() const noexcept final override { return "LEAF error"; }
			std::string message( int condition ) const final override { return name(); }
		public:
			~leaf_category() noexcept final override { }
		};

		template <class=void>
		struct get_error_category
		{
			static leaf_category cat;
		};

		template <class T>
		leaf_category get_error_category<T>::cat;

		inline int import_error_code( std::error_code const & ec ) noexcept
		{
			if( int err_id = ec.value() )
			{
				std::error_category const & cat = get_error_category<>::cat;
				if( &ec.category()==&cat )
				{
					BOOST_LEAF_ASSERT((err_id&3)==1);
					return (err_id&~3)|1;
				}
				else
				{
					err_id = new_id();
					(void) load_slot(err_id, ec);
					return (err_id&~3)|1;
				}
			}
			else
				return 0;
		}
	}

	inline bool is_error_id( std::error_code const & ec ) noexcept
	{
		bool res = (&ec.category() == &leaf_detail::get_error_category<>::cat);
		BOOST_LEAF_ASSERT(!res || !ec.value() || ((ec.value()&3)==1));
		return res;
	}

	////////////////////////////////////////

	class error_id;

	namespace leaf_detail
	{
		BOOST_LEAF_CONSTEXPR error_id make_error_id(int) noexcept;
	}

	class error_id
	{
		friend error_id BOOST_LEAF_CONSTEXPR leaf_detail::make_error_id(int) noexcept;

		int value_;

		BOOST_LEAF_CONSTEXPR explicit error_id( int value ) noexcept:
			value_(value)
		{
			BOOST_LEAF_ASSERT(value_==0 || ((value_&3)==1));
		}

	public:

		BOOST_LEAF_CONSTEXPR error_id() noexcept:
			value_(0)
		{
		}

		error_id( std::error_code const & ec ) noexcept:
			value_(leaf_detail::import_error_code(ec))
		{
			BOOST_LEAF_ASSERT(!value_ || ((value_&3)==1));
		}

		BOOST_LEAF_CONSTEXPR error_id load() const noexcept
		{
			return *this;
		}

		template <class... Item>
		BOOST_LEAF_CONSTEXPR error_id load( Item && ... item ) const noexcept
		{
			if( int err_id = value() )
			{
				int const unused[ ] = { 42, leaf_detail::load_item<Item>::load(err_id, std::forward<Item>(item))... };
				(void) unused;
			}
			return *this;
		}

		std::error_code to_error_code() const noexcept
		{
			return std::error_code(value_, leaf_detail::get_error_category<>::cat);
		}

		BOOST_LEAF_CONSTEXPR int value() const noexcept
		{
			if( int v = value_ )
			{
				BOOST_LEAF_ASSERT((v&3)==1);
				return (v&~3)|1;
			}
			else
				return 0;
		}

		BOOST_LEAF_CONSTEXPR explicit operator bool() const noexcept
		{
			return value_ != 0;
		}

		BOOST_LEAF_CONSTEXPR friend bool operator==( error_id a, error_id b ) noexcept
		{
			return a.value_ == b.value_;
		}

		BOOST_LEAF_CONSTEXPR friend bool operator!=( error_id a, error_id b ) noexcept
		{
			return !(a == b);
		}

		BOOST_LEAF_CONSTEXPR friend bool operator<( error_id a, error_id b ) noexcept
		{
			return a.value_ < b.value_;
		}

		friend std::ostream & operator<<( std::ostream & os, error_id x )
		{
			return os << x.value_;
		}

		BOOST_LEAF_CONSTEXPR void load_source_location_( char const * file, int line, char const * function ) const noexcept
		{
			BOOST_LEAF_ASSERT(file&&*file);
			BOOST_LEAF_ASSERT(line>0);
			BOOST_LEAF_ASSERT(function&&*function);
			BOOST_LEAF_ASSERT(value_);
			(void) load(e_source_location {file,line,function});
		}
	};

	namespace leaf_detail
	{
		BOOST_LEAF_CONSTEXPR inline error_id make_error_id( int err_id ) noexcept
		{
			BOOST_LEAF_ASSERT(err_id==0 || (err_id&3)==1);
			return error_id((err_id&~3)|1);
		}
	}

	inline error_id new_error() noexcept
	{
		return leaf_detail::make_error_id(leaf_detail::new_id());
	}

	template <class... Item>
	inline error_id new_error( Item && ... item ) noexcept
	{
		return leaf_detail::make_error_id(leaf_detail::new_id()).load(std::forward<Item>(item)...);
	}

	inline error_id current_error() noexcept
	{
		return leaf_detail::make_error_id(leaf_detail::current_id());
	}

	namespace leaf_detail
	{
		template <class... E>
		inline error_id new_error_at( char const * file, int line, char const * function ) noexcept
		{
			BOOST_LEAF_ASSERT(file&&*file);
			BOOST_LEAF_ASSERT(line>0);
			BOOST_LEAF_ASSERT(function&&*function);
			e_source_location sl { file, line, function }; // Temp object MSVC workaround
			return new_error(std::move(sl));
		}
	}

	////////////////////////////////////////////

	class polymorphic_context
	{
	protected:
		polymorphic_context() noexcept = default;
		~polymorphic_context() noexcept = default;
	public:
		virtual error_id propagate_captured_errors() noexcept = 0;
		virtual void activate() noexcept = 0;
		virtual void deactivate() noexcept = 0;
		virtual void propagate() noexcept = 0;
		virtual bool is_active() const noexcept = 0;
		virtual void print( std::ostream & ) const = 0;
		error_id captured_id_;
	};

	using context_ptr = std::shared_ptr<polymorphic_context>;

	////////////////////////////////////////////

	template <class Ctx>
	class context_activator
	{
		context_activator( context_activator const & ) = delete;
		context_activator & operator=( context_activator const & ) = delete;

#if !defined(BOOST_LEAF_NO_EXCEPTIONS) && BOOST_LEAF_STD_UNCAUGHT_EXCEPTIONS
		int const uncaught_exceptions_;
#endif
		Ctx * ctx_;

	public:

		explicit BOOST_LEAF_CONSTEXPR BOOST_LEAF_ALWAYS_INLINE context_activator(Ctx & ctx) noexcept:
#if !defined(BOOST_LEAF_NO_EXCEPTIONS) && BOOST_LEAF_STD_UNCAUGHT_EXCEPTIONS
			uncaught_exceptions_(std::uncaught_exceptions()),
#endif
			ctx_(ctx.is_active() ? 0 : &ctx)
		{
			if( ctx_ )
				ctx_->activate();
		}

		BOOST_LEAF_CONSTEXPR BOOST_LEAF_ALWAYS_INLINE context_activator( context_activator && x ) noexcept:
#if !defined(BOOST_LEAF_NO_EXCEPTIONS) && BOOST_LEAF_STD_UNCAUGHT_EXCEPTIONS
			uncaught_exceptions_(x.uncaught_exceptions_),
#endif
			ctx_(x.ctx_)
		{
			x.ctx_ = 0;
		}

		BOOST_LEAF_ALWAYS_INLINE ~context_activator() noexcept
		{
			if( !ctx_ )
				return;
			if( ctx_->is_active() )
				ctx_->deactivate();
#ifndef BOOST_LEAF_NO_EXCEPTIONS
#	if BOOST_LEAF_STD_UNCAUGHT_EXCEPTIONS
			if( std::uncaught_exceptions() > uncaught_exceptions_ )
#	else
			if( std::uncaught_exception() )
#	endif
				ctx_->propagate();
#endif
		}
	};

	template <class Ctx>
	BOOST_LEAF_CONSTEXPR BOOST_LEAF_ALWAYS_INLINE context_activator<Ctx> activate_context(Ctx & ctx) noexcept
	{
		return context_activator<Ctx>(ctx);
	}

	////////////////////////////////////////////

	template <class R>
	struct is_result_type: std::false_type
	{
	};

	template <class R>
	struct is_result_type<R const>: is_result_type<R>
	{
	};

	namespace leaf_detail
	{
		template <class R, bool IsResult = is_result_type<R>::value>
		struct is_result_tag;

		template <class R>
		struct is_result_tag<R, false>
		{
		};

		template <class R>
		struct is_result_tag<R, true>
		{
		};
	}

} }

#undef BOOST_LEAF_THREAD_LOCAL

#endif
// <<< #include <boost/leaf/error.hpp>
#line 18 "boost/leaf/exception.hpp"
#include <exception>

#define BOOST_LEAF_EXCEPTION ::boost::leaf::leaf_detail::inject_loc{__FILE__,__LINE__,__FUNCTION__}+::boost::leaf::exception
#define BOOST_LEAF_THROW_EXCEPTION ::boost::leaf::leaf_detail::throw_with_loc{__FILE__,__LINE__,__FUNCTION__}+::boost::leaf::exception

#ifdef BOOST_LEAF_NO_EXCEPTIONS

namespace boost
{
	[[noreturn]] void throw_exception( std::exception const & ); // user defined
}

namespace boost { namespace leaf {

	template <class T>
	[[noreturn]] void throw_exception( T const & e )
	{
		::boost::throw_exception(e);
	}

} }

#else

namespace boost { namespace leaf {

	template <class T>
	[[noreturn]] void throw_exception( T const & e )
	{
		throw e;
	}

} }

#endif

////////////////////////////////////////

namespace boost { namespace leaf {

	namespace leaf_detail
	{
		struct throw_with_loc
		{
			char const * const file;
			int const line;
			char const * const fn;

			template <class Ex>
			[[noreturn]] friend void operator+( throw_with_loc loc, Ex const & ex )
			{
				ex.load_source_location_(loc.file, loc.line, loc.fn);
				::boost::leaf::throw_exception(ex);
			}
		};
	}

} }

////////////////////////////////////////

namespace boost { namespace leaf {

	namespace leaf_detail
	{
		inline void enforce_std_exception( std::exception const & ) noexcept { }

		class exception_base
		{
			std::shared_ptr<void const> auto_id_bump_;
		public:

			virtual error_id get_error_id() const noexcept = 0;

		protected:

			exception_base():
				auto_id_bump_(0, [](void const *) { (void) new_id(); })
			{
			}

			~exception_base() noexcept { }
		};

		template <class Ex>
		class exception:
			public Ex,
			public exception_base,
			public error_id
		{
			error_id get_error_id() const noexcept final override
			{
				return *this;
			}

		public:

			exception( exception const & ) = default;
			exception( exception && ) = default;

			BOOST_LEAF_CONSTEXPR exception( error_id id, Ex && ex ) noexcept:
				Ex(std::move(ex)),
				error_id(id)
			{
				leaf_detail::enforce_std_exception(*this);
			}

			explicit BOOST_LEAF_CONSTEXPR exception( error_id id ) noexcept:
				error_id(id)
			{
				leaf_detail::enforce_std_exception(*this);
			}
		};

		template <class... T>
		struct at_least_one_derives_from_std_exception;

		template <>
		struct at_least_one_derives_from_std_exception<>: std::false_type { };

		template <class T, class... Rest>
		struct at_least_one_derives_from_std_exception<T, Rest...>
		{
			constexpr static const bool value = std::is_base_of<std::exception,T>::value || at_least_one_derives_from_std_exception<Rest...>::value;
		};
	}

	template <class Ex, class... E>
	inline typename std::enable_if<std::is_base_of<std::exception,Ex>::value, leaf_detail::exception<Ex>>::type exception( Ex && ex, E && ... e ) noexcept
	{
		static_assert(!leaf_detail::at_least_one_derives_from_std_exception<E...>::value, "Error objects passed to leaf::exception may not derive from std::exception");
		auto id = leaf::new_error(std::forward<E>(e)...);
		return leaf_detail::exception<Ex>(id, std::forward<Ex>(ex));
	}

	template <class E1, class... E>
	inline typename std::enable_if<!std::is_base_of<std::exception,E1>::value, leaf_detail::exception<std::exception>>::type exception( E1 && car, E && ... cdr ) noexcept
	{
		static_assert(!leaf_detail::at_least_one_derives_from_std_exception<E...>::value, "Error objects passed to leaf::exception may not derive from std::exception");
		auto id = leaf::new_error(std::forward<E1>(car), std::forward<E>(cdr)...);
		return leaf_detail::exception<std::exception>(id);
	}

	inline leaf_detail::exception<std::exception> exception() noexcept
	{
		return leaf_detail::exception<std::exception>(leaf::new_error());
	}

} }

#endif
// <<< #include <boost/leaf/exception.hpp>
#line 18 "boost/leaf/capture.hpp"
// >>> #include <boost/leaf/on_error.hpp>
#line 1 "boost/leaf/on_error.hpp"
#ifndef BOOST_LEAF_ON_ERROR_HPP_INCLUDED
#define BOOST_LEAF_ON_ERROR_HPP_INCLUDED

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


namespace boost { namespace leaf {

	class error_monitor
	{
#if !defined(BOOST_LEAF_NO_EXCEPTIONS) && BOOST_LEAF_STD_UNCAUGHT_EXCEPTIONS
		int const uncaught_exceptions_;
#endif
		int const err_id_;

	public:

		error_monitor() noexcept:
#if !defined(BOOST_LEAF_NO_EXCEPTIONS) && BOOST_LEAF_STD_UNCAUGHT_EXCEPTIONS
			uncaught_exceptions_(std::uncaught_exceptions()),
#endif
			err_id_(leaf_detail::current_id())
		{
		}

		int check_id() const noexcept
		{
			int err_id = leaf_detail::current_id();
			if( err_id != err_id_ )
				return err_id;
			else
			{
#ifndef BOOST_LEAF_NO_EXCEPTIONS
#	if BOOST_LEAF_STD_UNCAUGHT_EXCEPTIONS
				if( std::uncaught_exceptions() > uncaught_exceptions_ )
#	else
				if( std::uncaught_exception() )
#	endif
					return leaf_detail::new_id();
#endif
				return 0;
			}
		}

		int get_id() const noexcept
		{
			int err_id = leaf_detail::current_id();
			if( err_id != err_id_ )
				return err_id;
			else
				return leaf_detail::new_id();
		}

		error_id check() const noexcept
		{
			return leaf_detail::make_error_id(check_id());
		}

		error_id assigned_error_id() const noexcept
		{
			return leaf_detail::make_error_id(get_id());
		}
	};

	////////////////////////////////////////////

	namespace leaf_detail
	{
		template <int I, class Tuple>
		struct tuple_for_each_preload
		{
			BOOST_LEAF_CONSTEXPR static void trigger( Tuple & tup, int err_id ) noexcept
			{
				BOOST_LEAF_ASSERT((err_id&3)==1);
				tuple_for_each_preload<I-1,Tuple>::trigger(tup,err_id);
				std::get<I-1>(tup).trigger(err_id);
			}
		};

		template <class Tuple>
		struct tuple_for_each_preload<0, Tuple>
		{
			BOOST_LEAF_CONSTEXPR static void trigger( Tuple const &, int ) noexcept { }
		};

		template <class E>
		class preloaded_item
		{
			using decay_E = typename std::decay<E>::type;
			slot<decay_E> * s_;
			decay_E e_;

		public:

			BOOST_LEAF_CONSTEXPR preloaded_item( E && e ):
				s_(tl_slot_ptr<decay_E>()),
				e_(std::forward<E>(e))
			{
			}

			BOOST_LEAF_CONSTEXPR void trigger( int err_id ) noexcept
			{
				BOOST_LEAF_ASSERT((err_id&3)==1);
				if( s_ )
				{
					if( !s_->has_value(err_id) )
						s_->put(err_id, std::move(e_));
				}
#if BOOST_LEAF_DIAGNOSTICS
				else
				{
					int c = tl_unexpected_enabled_counter();
					BOOST_LEAF_ASSERT(c>=0);
					if( c )
						load_unexpected(err_id, std::move(e_));
				}
#endif
			}
		};

		template <class F>
		class deferred_item
		{
			typedef decltype(std::declval<F>()()) E;
			slot<E> * s_;
			F f_;

		public:

			BOOST_LEAF_CONSTEXPR deferred_item( F && f ) noexcept:
				s_(tl_slot_ptr<E>()),
				f_(std::forward<F>(f))
			{
			}

			BOOST_LEAF_CONSTEXPR void trigger( int err_id ) noexcept
			{
				BOOST_LEAF_ASSERT((err_id&3)==1);
				if( s_ )
				{
					if( !s_->has_value(err_id) )
						s_->put(err_id, f_());
				}
#if BOOST_LEAF_DIAGNOSTICS
				else
				{
					int c = tl_unexpected_enabled_counter();
					BOOST_LEAF_ASSERT(c>=0);
					if( c )
						load_unexpected(err_id, std::forward<E>(f_()));
				}
#endif
			}
		};

		template <class F, class A0 = fn_arg_type<F,0>, int arity = function_traits<F>::arity>
		class accumulating_item;

		template <class F, class A0>
		class accumulating_item<F, A0 &, 1>
		{
			using E = A0;
			slot<E> * s_;
			F f_;

		public:

			BOOST_LEAF_CONSTEXPR accumulating_item( F && f ) noexcept:
				s_(tl_slot_ptr<E>()),
				f_(std::forward<F>(f))
			{
			}

			BOOST_LEAF_CONSTEXPR void trigger( int err_id ) noexcept
			{
				BOOST_LEAF_ASSERT((err_id&3)==1);
				if( s_ )
					if( E * e = s_->has_value(err_id) )
						(void) f_(*e);
					else
						(void) f_(s_->put(err_id, E()));
			}
		};

		template <class... Item>
		class preloaded
		{
			preloaded & operator=( preloaded const & ) = delete;

			std::tuple<Item...> p_;
			bool moved_;
			error_monitor id_;

		public:

			BOOST_LEAF_CONSTEXPR explicit preloaded( Item && ... i ):
				p_(std::forward<Item>(i)...),
				moved_(false)
			{
			}

			BOOST_LEAF_CONSTEXPR preloaded( preloaded && x ) noexcept:
				p_(std::move(x.p_)),
				moved_(false),
				id_(std::move(x.id_))
			{
				x.moved_ = true;
			}

			~preloaded() noexcept
			{
				if( moved_ )
					return;
				if( auto id = id_.check_id() )
					leaf_detail::tuple_for_each_preload<sizeof...(Item),decltype(p_)>::trigger(p_,id);
			}
		};

		template <class T, int arity = function_traits<T>::arity>
		struct deduce_item_type;

		template <class T>
		struct deduce_item_type<T, -1>
		{
			using type = preloaded_item<T>;
		};

		template <class F>
		struct deduce_item_type<F, 0>
		{
			using type = deferred_item<F>;
		};

		template <class F>
		struct deduce_item_type<F, 1>
		{
			using type = accumulating_item<F>;
		};
	} // leaf_detail

	template <class... Item>
	BOOST_LEAF_NODISCARD BOOST_LEAF_CONSTEXPR inline leaf_detail::preloaded<typename leaf_detail::deduce_item_type<Item>::type...> on_error( Item && ... i )
	{
		return leaf_detail::preloaded<typename leaf_detail::deduce_item_type<Item>::type...>(std::forward<Item>(i)...);
	}

} }

#endif
// <<< #include <boost/leaf/on_error.hpp>
#line 19 "boost/leaf/capture.hpp"
#include <memory>

namespace boost { namespace leaf {

#ifdef BOOST_LEAF_NO_EXCEPTIONS

	namespace leaf_detail
	{
		template <class R, class F, class... A>
		inline decltype(std::declval<F>()(std::forward<A>(std::declval<A>())...)) capture_impl(is_result_tag<R, false>, context_ptr && ctx, F && f, A... a) noexcept
		{
			auto active_context = activate_context(*ctx);
			return std::forward<F>(f)(std::forward<A>(a)...);
		}

		template <class R, class F, class... A>
		inline decltype(std::declval<F>()(std::forward<A>(std::declval<A>())...)) capture_impl(is_result_tag<R, true>, context_ptr && ctx, F && f, A... a) noexcept
		{
			auto active_context = activate_context(*ctx);
			if( auto r = std::forward<F>(f)(std::forward<A>(a)...) )
				return r;
			else
			{
				ctx->captured_id_ = r.error();
				return std::move(ctx);
			}
		}

		template <class R, class Future>
		inline decltype(std::declval<Future>().get()) future_get_impl(is_result_tag<R, false>, Future & fut ) noexcept
		{
			return fut.get();
		}

		template <class R, class Future>
		inline decltype(std::declval<Future>().get()) future_get_impl(is_result_tag<R, true>, Future & fut ) noexcept
		{
			if( auto r = fut.get() )
				return r;
			else
				return error_id(r.error()); // unloads
		}
	}

#else

	namespace leaf_detail
	{
		class capturing_exception:
			public std::exception
		{
			std::exception_ptr ex_;
			context_ptr ctx_;

		public:

			capturing_exception(std::exception_ptr && ex, context_ptr && ctx) noexcept:
				ex_(std::move(ex)),
				ctx_(std::move(ctx))
			{
				BOOST_LEAF_ASSERT(ex_);
				BOOST_LEAF_ASSERT(ctx_);
				BOOST_LEAF_ASSERT(ctx_->captured_id_);
			}

			[[noreturn]] void unload_and_rethrow_original_exception() const
			{
				BOOST_LEAF_ASSERT(ctx_->captured_id_);
				auto active_context = activate_context(*ctx_);
				id_factory<>::current_id = ctx_->captured_id_.value();
				std::rethrow_exception(ex_);
			}

			void print( std::ostream & os ) const
			{
				ctx_->print(os);
			}
		};

		template <class R, class F, class... A>
		inline decltype(std::declval<F>()(std::forward<A>(std::declval<A>())...)) capture_impl(is_result_tag<R, false>, context_ptr && ctx, F && f, A... a)
		{
			auto active_context = activate_context(*ctx);
			error_monitor cur_err;
			try
			{
				return std::forward<F>(f)(std::forward<A>(a)...);
			}
			catch( capturing_exception const & )
			{
				throw;
			}
			catch( exception_base const & e )
			{
				ctx->captured_id_ = e.get_error_id();
				throw_exception( capturing_exception(std::current_exception(), std::move(ctx)) );
			}
			catch(...)
			{
				ctx->captured_id_ = cur_err.assigned_error_id();
				throw_exception( capturing_exception(std::current_exception(), std::move(ctx)) );
			}
		}

		template <class R, class F, class... A>
		inline decltype(std::declval<F>()(std::forward<A>(std::declval<A>())...)) capture_impl(is_result_tag<R, true>, context_ptr && ctx, F && f, A... a)
		{
			auto active_context = activate_context(*ctx);
			error_monitor cur_err;
			try
			{
				if( auto && r = std::forward<F>(f)(std::forward<A>(a)...) )
					return std::move(r);
				else
				{
					ctx->captured_id_ = r.error();
					return std::move(ctx);
				}
			}
			catch( capturing_exception const & )
			{
				throw;
			}
			catch( exception_base const & e )
			{
				ctx->captured_id_ = e.get_error_id();
				throw_exception( capturing_exception(std::current_exception(), std::move(ctx)) );
			}
			catch(...)
			{
				ctx->captured_id_ = cur_err.assigned_error_id();
				throw_exception( capturing_exception(std::current_exception(), std::move(ctx)) );
			}
		}

		template <class R, class Future>
		inline decltype(std::declval<Future>().get()) future_get_impl(is_result_tag<R, false>, Future & fut )
		{
			try
			{
				return fut.get();
			}
			catch( leaf_detail::capturing_exception const & cap )
			{
				cap.unload_and_rethrow_original_exception();
			}
		}

		template <class R, class Future>
		inline decltype(std::declval<Future>().get()) future_get_impl(is_result_tag<R, true>, Future & fut )
		{
			try
			{
				if( auto r = fut.get() )
					return r;
				else
					return error_id(r.error()); // unloads
			}
			catch( leaf_detail::capturing_exception const & cap )
			{
				cap.unload_and_rethrow_original_exception();
			}
		}
	}

#endif

	template <class F, class... A>
	inline decltype(std::declval<F>()(std::forward<A>(std::declval<A>())...)) capture(context_ptr && ctx, F && f, A... a)
	{
		using namespace leaf_detail;
		return capture_impl(is_result_tag<decltype(std::declval<F>()(std::forward<A>(std::declval<A>())...))>(), std::move(ctx), std::forward<F>(f), std::forward<A>(a)...);
	}

	template <class Future>
	inline decltype(std::declval<Future>().get()) future_get( Future & fut )
	{
		using namespace leaf_detail;
		return future_get_impl(is_result_tag<decltype(std::declval<Future>().get())>(), fut);
	}

	////////////////////////////////////////

#ifndef BOOST_LEAF_NO_EXCEPTIONS

	template <class T>
	class result;

	namespace leaf_detail
	{
		inline error_id catch_exceptions_helper( std::exception const & ex, leaf_detail_mp11::mp_list<> )
		{
			return leaf::new_error(std::current_exception());
		}

		template <class Ex1, class... Ex>
		inline error_id catch_exceptions_helper( std::exception const & ex, leaf_detail_mp11::mp_list<Ex1,Ex...> )
		{
			if( Ex1 const * p = dynamic_cast<Ex1 const *>(&ex) )
				return catch_exceptions_helper(ex, leaf_detail_mp11::mp_list<Ex...>{ }).load(*p);
			else
				return catch_exceptions_helper(ex, leaf_detail_mp11::mp_list<Ex...>{ });
		}

		template <class T>
		struct deduce_exception_to_result_return_type_impl
		{
			using type = result<T>;
		};

		template <class T>
		struct deduce_exception_to_result_return_type_impl<result<T>>
		{
			using type = result<T>;
		};

		template <class T>
		using deduce_exception_to_result_return_type = typename deduce_exception_to_result_return_type_impl<T>::type;
	}

	template <class... Ex, class F>
	inline leaf_detail::deduce_exception_to_result_return_type<leaf_detail::fn_return_type<F>> exception_to_result( F && f ) noexcept
	{
		try
		{
			return std::forward<F>(f)();
		}
		catch( std::exception const & ex )
		{
			return leaf_detail::catch_exceptions_helper(ex, leaf_detail_mp11::mp_list<Ex...>());
		}
		catch(...)
		{
			return leaf::new_error(std::current_exception());
		}
	};

#endif

} }

#endif
// <<< #include <boost/leaf/capture.hpp>
#line 11 "../../include/boost/leaf/detail/all.hpp"
// >>> #include <boost/leaf/common.hpp>
#line 1 "boost/leaf/common.hpp"
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
// <<< #include <boost/leaf/common.hpp>
#line 12 "../../include/boost/leaf/detail/all.hpp"
// >>> #include <boost/leaf/context.hpp>
#line 1 "boost/leaf/context.hpp"
#ifndef BOOST_LEAF_CONTEXT_HPP_INCLUDED
#define BOOST_LEAF_CONTEXT_HPP_INCLUDED

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


namespace boost { namespace leaf {

	namespace leaf_detail
	{
		template <int I, class Tuple>
		struct tuple_for_each
		{
			BOOST_LEAF_CONSTEXPR static void activate( Tuple & tup ) noexcept
			{
				tuple_for_each<I-1,Tuple>::activate(tup);
				std::get<I-1>(tup).activate();
			}

			BOOST_LEAF_CONSTEXPR static void deactivate( Tuple & tup ) noexcept
			{
				std::get<I-1>(tup).deactivate();
				tuple_for_each<I-1,Tuple>::deactivate(tup);
			}

			BOOST_LEAF_CONSTEXPR static void propagate( Tuple & tup ) noexcept
			{
				auto & sl = std::get<I-1>(tup);
				sl.propagate();
				tuple_for_each<I-1,Tuple>::propagate(tup);
			}

			BOOST_LEAF_CONSTEXPR static void propagate_captured( Tuple & tup, int err_id ) noexcept
			{
				auto & sl = std::get<I-1>(tup);
				if( sl.has_value(err_id) )
					leaf_detail::load_slot(err_id, std::move(sl).value(err_id));
				tuple_for_each<I-1,Tuple>::propagate_captured(tup, err_id);
			}

			static void print( std::ostream & os, void const * tup, int key_to_print )
			{
				BOOST_LEAF_ASSERT(tup!=0);
				tuple_for_each<I-1,Tuple>::print(os, tup, key_to_print);
				std::get<I-1>(*static_cast<Tuple const *>(tup)).print(os, key_to_print);
			}
		};

		template <class Tuple>
		struct tuple_for_each<0, Tuple>
		{
			BOOST_LEAF_CONSTEXPR static void activate( Tuple & ) noexcept { }
			BOOST_LEAF_CONSTEXPR static void deactivate( Tuple & ) noexcept { }
			BOOST_LEAF_CONSTEXPR static void propagate( Tuple & tup ) noexcept { }
			BOOST_LEAF_CONSTEXPR static void propagate_captured( Tuple & tup, int ) noexcept { }
			static void print( std::ostream &, void const *, int ) { }
		};
	}

	////////////////////////////////////////////

	namespace leaf_detail
	{
		class e_unexpected_count;
		class e_unexpected_info;

		template <class T> struct requires_unexpected { constexpr static bool value = false; };
		template <class T> struct requires_unexpected<T const> { constexpr static bool value = requires_unexpected<T>::value; };
		template <class T> struct requires_unexpected<T const &> { constexpr static bool value = requires_unexpected<T>::value; };
		template <class T> struct requires_unexpected<T const *> { constexpr static bool value = requires_unexpected<T>::value; };
		template <> struct requires_unexpected<e_unexpected_count> { constexpr static bool value = true; };
		template <> struct requires_unexpected<e_unexpected_info> { constexpr static bool value = true; };

		template <class L>
		struct unexpected_requested;

		template <template <class ...> class L>
		struct unexpected_requested<L<>>
		{
			constexpr static bool value = false;
		};

		template <template <class...> class L, template <class> class S, class Car, class... Cdr>
		struct unexpected_requested<L<S<Car>, S<Cdr>...>>
		{
			constexpr static bool value = requires_unexpected<Car>::value || unexpected_requested<L<S<Cdr>...>>::value;
		};
	}

	////////////////////////////////////////////

	class error_info;
	class diagnostic_info;
	class verbose_diagnostic_info;

	namespace leaf_detail
	{
		template <class T> struct translate_type_impl { using type = T; };
		template <class T> struct translate_type_impl<T const> { using type = T; };
		template <class T> struct translate_type_impl<T const *> { using type = T; };
		template <class T> struct translate_type_impl<T const &> { using type = T; };
		template <class T> struct translate_type_impl<T *> { using type = T; };
		template <class T> struct translate_type_impl<T &> { using type = T; };

		template <> struct translate_type_impl<diagnostic_info>; // Only take leaf::diagnostic_info by const &
		template <> struct translate_type_impl<diagnostic_info const>; // Only take leaf::diagnostic_info by const &
		template <> struct translate_type_impl<diagnostic_info const *>; // Only take leaf::diagnostic_info by const &
		template <> struct translate_type_impl<diagnostic_info const &> { using type = e_unexpected_count; };

		template <> struct translate_type_impl<verbose_diagnostic_info>; // Only take leaf::verbose_diagnostic_info by const &
		template <> struct translate_type_impl<verbose_diagnostic_info const>; // Only take leaf::verbose_diagnostic_info by const &
		template <> struct translate_type_impl<verbose_diagnostic_info const *>; // Only take leaf::verbose_diagnostic_info by const &
		template <> struct translate_type_impl<verbose_diagnostic_info const &> { using type = e_unexpected_info; };

		template <> struct translate_type_impl<std::error_code &>;

		template <class T>
		using translate_type = typename translate_type_impl<T>::type;

		template <class... T>
		struct translate_list_impl;

		template <template<class...> class L, class... T>
		struct translate_list_impl<L<T...>>
		{
			using type = leaf_detail_mp11::mp_list<translate_type<T>...>;
		};

		template <class L> using translate_list = typename translate_list_impl<L>::type;

		template <class T> struct does_not_participate_in_context_deduction: std::false_type { };
		template <> struct does_not_participate_in_context_deduction<error_info>: std::true_type { };
		template <> struct does_not_participate_in_context_deduction<void>: std::true_type { };
#if !BOOST_LEAF_DIAGNOSTICS
		template <> struct does_not_participate_in_context_deduction<e_unexpected_count>: std::true_type { };
		template <> struct does_not_participate_in_context_deduction<e_unexpected_info>: std::true_type { };
#endif

		template <class L>
		struct transform_e_type_list_impl;

		template <template<class...> class L, class... T>
		struct transform_e_type_list_impl<L<T...>>
		{
			using type =
				leaf_detail_mp11::mp_remove_if<
					leaf_detail_mp11::mp_unique<
						translate_list<L<T...>>
					>,
					does_not_participate_in_context_deduction
				>;
		};

		template <class L> using transform_e_type_list = typename transform_e_type_list_impl<L>::type;

		template <class L>
		struct deduce_e_tuple_impl;

		template <template <class...> class L, class... E>
		struct deduce_e_tuple_impl<L<E...>>
		{
			using type = std::tuple<slot<E>...>;
		};

		template <class... E>
		using deduce_e_tuple = typename deduce_e_tuple_impl<leaf_detail::transform_e_type_list<leaf_detail_mp11::mp_list<E...>>>::type;
	}

	////////////////////////////////////////////

	template <class... Ex>
	class catch_;

	namespace leaf_detail
	{
		template <class... E>
		class context_base
		{
			context_base( context_base const & ) = delete;
			context_base & operator=( context_base const & ) = delete;

		public:

			using Tup = leaf_detail::deduce_e_tuple<E...>;

		private:

			Tup tup_;
#if !defined(BOOST_LEAF_NO_THREADS) && !defined(NDEBUG)
			std::thread::id thread_id_;
#endif
			bool is_active_;

		protected:

			BOOST_LEAF_CONSTEXPR error_id propagate_captured_errors( error_id err_id ) noexcept
			{
				tuple_for_each<std::tuple_size<Tup>::value,Tup>::propagate_captured(tup_, err_id.value());
				return err_id;
			}

			BOOST_LEAF_CONSTEXPR context_base( context_base && x ) noexcept:
				tup_(std::move(x.tup_)),
				is_active_(false)
			{
				BOOST_LEAF_ASSERT(!x.is_active());
			}

		public:

			BOOST_LEAF_CONSTEXPR context_base() noexcept:
				is_active_(false)
			{
			}

			~context_base() noexcept
			{
				BOOST_LEAF_ASSERT(!is_active());
			}

			BOOST_LEAF_CONSTEXPR Tup const & tup() const noexcept
			{
				return tup_;
			}

			BOOST_LEAF_CONSTEXPR Tup & tup() noexcept
			{
				return tup_;
			}

			BOOST_LEAF_CONSTEXPR void activate() noexcept
			{
				using namespace leaf_detail;
				BOOST_LEAF_ASSERT(!is_active());
				tuple_for_each<std::tuple_size<Tup>::value,Tup>::activate(tup_);
#if BOOST_LEAF_DIAGNOSTICS
				if( unexpected_requested<Tup>::value )
					++tl_unexpected_enabled_counter();
#endif
#if !defined(BOOST_LEAF_NO_THREADS) && !defined(NDEBUG)
				thread_id_ = std::this_thread::get_id();
#endif
				is_active_ = true;
			}

			BOOST_LEAF_CONSTEXPR void deactivate() noexcept
			{
				using namespace leaf_detail;
				BOOST_LEAF_ASSERT(is_active());
				is_active_ = false;
#if !defined(BOOST_LEAF_NO_THREADS) && !defined(NDEBUG)
				BOOST_LEAF_ASSERT(std::this_thread::get_id() == thread_id_);
				thread_id_ = std::thread::id();
#endif
#if BOOST_LEAF_DIAGNOSTICS
				if( unexpected_requested<Tup>::value )
					--tl_unexpected_enabled_counter();
#endif
				tuple_for_each<std::tuple_size<Tup>::value,Tup>::deactivate(tup_);
			}

			BOOST_LEAF_CONSTEXPR void propagate() noexcept
			{
				tuple_for_each<std::tuple_size<Tup>::value,Tup>::propagate(tup_);
			}

			BOOST_LEAF_CONSTEXPR bool is_active() const noexcept
			{
				return is_active_;
			}

			void print( std::ostream & os ) const
			{
				leaf_detail::tuple_for_each<std::tuple_size<Tup>::value,Tup>::print(os, &tup_, 0);
			}

			template <class R, class... H>
			BOOST_LEAF_CONSTEXPR R handle_error( error_id, H && ... ) const;

			template <class R, class... H>
			BOOST_LEAF_CONSTEXPR R handle_error( error_id, H && ... );

			template <class TryBlock, class... H>
			decltype(std::declval<TryBlock>()()) try_catch_( TryBlock &&, H && ... );
		};

		template <class T> struct requires_catch { constexpr static bool value = std::is_base_of<std::exception, typename std::decay<T>::type>::value; };
		template <class... Ex> struct requires_catch<catch_<Ex...>>: std::true_type { };

		template <class... E>
		struct catch_requested;

		template <>
		struct catch_requested<>
		{
			constexpr static bool value = false;
		};

		template <class Car, class... Cdr>
		struct catch_requested<Car, Cdr...>
		{
			constexpr static bool value = requires_catch<Car>::value || catch_requested<Cdr...>::value;
		};

		template <bool CatchRequested, class... E>
		struct select_context_base_impl;

		template <class...>
		class nocatch_context;

		template <class... E>
		struct select_context_base_impl<false, E...>
		{
			using type = nocatch_context<E...>;
		};

		template <class...>
		class catch_context;

		template <class... E>
		struct select_context_base_impl<true, E...>
		{
			using type = catch_context<E...>;
		};

		template <class... E>
		using select_context_base = typename select_context_base_impl<catch_requested<E...>::value, E...>::type;
	}

	template <class... E>
	class context: public leaf_detail::select_context_base<E...>
	{
	};

	////////////////////////////////////////

	namespace leaf_detail
	{
		template <class HandlerL>
		struct handler_args_impl;

		template <template <class...> class L, class... H>
		struct handler_args_impl<L<H...>>
		{
			using type = leaf_detail_mp11::mp_append<fn_mp_args<H>...>;
		};

		template <class HandlerL>
		using handler_args = typename handler_args_impl<HandlerL>::type;

		template <class TypeList>
		struct deduce_context_impl;

		template <template <class...> class L, class... E>
		struct deduce_context_impl<L<E...>>
		{
			using type = context<E...>;
		};

		template <class TypeList>
		using deduce_context = typename deduce_context_impl<TypeList>::type;

		template <class H>
		struct fn_mp_args_fwd
		{
			using type = fn_mp_args<H>;
		};

		template <class... H>
		struct fn_mp_args_fwd<std::tuple<H...> &>: fn_mp_args_fwd<std::tuple<H...>> { };

		template <class... H>
		struct fn_mp_args_fwd<std::tuple<H...>>
		{
			using type = leaf_detail_mp11::mp_append<typename fn_mp_args_fwd<H>::type...>;
		};

		template <class... H>
		struct context_type_from_handlers_impl
		{
			using type = deduce_context<leaf_detail_mp11::mp_append<typename fn_mp_args_fwd<H>::type...>>;
		};

		template <class Ctx>
		struct polymorphic_context_impl: polymorphic_context, Ctx
		{
			error_id propagate_captured_errors() noexcept final override { return Ctx::propagate_captured_errors(captured_id_); }
			void activate() noexcept final override { Ctx::activate(); }
			void deactivate() noexcept final override { Ctx::deactivate(); }
			void propagate() noexcept final override { Ctx::propagate(); }
			bool is_active() const noexcept final override { return Ctx::is_active(); }
			void print( std::ostream & os ) const final override { return Ctx::print(os); }
		};
	}

	template <class... H>
	using context_type_from_handlers = typename leaf_detail::context_type_from_handlers_impl<H...>::type;

	////////////////////////////////////////////

	template <class...  H>
	BOOST_LEAF_CONSTEXPR inline context_type_from_handlers<H...> make_context() noexcept
	{
		return { };
	}

	template <class...  H>
	BOOST_LEAF_CONSTEXPR inline context_type_from_handlers<H...> make_context( H && ... ) noexcept
	{
		return { };
	}

	////////////////////////////////////////////

	template <class...  H>
	inline context_ptr make_shared_context() noexcept
	{
		return std::make_shared<leaf_detail::polymorphic_context_impl<context_type_from_handlers<H...>>>();
	}

	template <class...  H>
	inline context_ptr make_shared_context( H && ... ) noexcept
	{
		return std::make_shared<leaf_detail::polymorphic_context_impl<context_type_from_handlers<H...>>>();
	}

} }

#endif
// <<< #include <boost/leaf/context.hpp>
#line 13 "../../include/boost/leaf/detail/all.hpp"
// >>> #include <boost/leaf/handle_error.hpp>
#line 1 "boost/leaf/handle_error.hpp"
#ifndef BOOST_LEAF_HANDLE_ERROR_HPP_INCLUDED
#define BOOST_LEAF_HANDLE_ERROR_HPP_INCLUDED

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


namespace boost { namespace leaf {

	namespace leaf_detail
	{
		class exception_info_base
		{
		protected:

			BOOST_LEAF_CONSTEXPR explicit exception_info_base( std::exception * ) noexcept;
			~exception_info_base() noexcept;

		public:

			std::exception * const ex_;

			virtual void print( std::ostream & os ) const = 0;
		};

		class exception_info_: public exception_info_base
		{
			exception_info_( exception_info_ const & ) = delete;
			exception_info_ & operator=( exception_info_ const & ) = delete;

			void print( std::ostream & os ) const final override;

		public:

			BOOST_LEAF_CONSTEXPR explicit exception_info_( std::exception * ex ) noexcept;
		};
	}

	class error_info
	{
		error_info & operator=( error_info const & ) = delete;

	protected:

		void print( std::ostream & os ) const
		{
			os << "Error ID = " << err_id_.value();
			if( xi_ )
				xi_->print(os);
		}

		BOOST_LEAF_CONSTEXPR error_info( error_info  const & ) noexcept = default;

	public:

		leaf_detail::exception_info_base const * const xi_;
		error_id const err_id_;

		BOOST_LEAF_CONSTEXPR explicit error_info( error_id id ) noexcept:
			xi_(0),
			err_id_(id)
		{
		}

		explicit error_info( leaf_detail::exception_info_ const & ) noexcept;

		BOOST_LEAF_CONSTEXPR error_id error() const noexcept
		{
			return err_id_;
		}

		BOOST_LEAF_CONSTEXPR bool exception_caught() const noexcept
		{
			return xi_!=0;
		}

		BOOST_LEAF_CONSTEXPR std::exception * exception() const noexcept
		{
			BOOST_LEAF_ASSERT(exception_caught());
			return xi_->ex_;
		}

		friend std::ostream & operator<<( std::ostream & os, error_info const & x )
		{
			os << "leaf::error_info: ";
			x.print(os);
			return os << '\n';
		}
	};

	////////////////////////////////////////

#if BOOST_LEAF_DIAGNOSTICS

	class diagnostic_info: public error_info
	{
		leaf_detail::e_unexpected_count const * e_uc_;
		void const * tup_;
		void (*print_)( std::ostream &, void const * tup, int key_to_print );

	public:

		template <class Tup>
		BOOST_LEAF_CONSTEXPR diagnostic_info( error_info const & ei, leaf_detail::e_unexpected_count const * e_uc, Tup const & tup ) noexcept:
			error_info(ei),
			e_uc_(e_uc),
			tup_(&tup),
			print_(&leaf_detail::tuple_for_each<std::tuple_size<Tup>::value, Tup>::print)
		{
		}

		friend std::ostream & operator<<( std::ostream & os, diagnostic_info const & x )
		{
			os << "leaf::diagnostic_info for ";
			x.print(os);
			os << ":\n";
			x.print_(os, x.tup_, x.err_id_.value());
			if( x.e_uc_  )
				x.e_uc_->print(os);
			return os;
		}
	};

	class verbose_diagnostic_info: public error_info
	{
		leaf_detail::e_unexpected_info const * e_ui_;
		void const * tup_;
		void (*print_)( std::ostream &, void const * tup, int key_to_print );

	public:

		template <class Tup>
		BOOST_LEAF_CONSTEXPR verbose_diagnostic_info( error_info const & ei, leaf_detail::e_unexpected_info const * e_ui, Tup const & tup ) noexcept:
			error_info(ei),
			e_ui_(e_ui),
			tup_(&tup),
			print_(&leaf_detail::tuple_for_each<std::tuple_size<Tup>::value, Tup>::print)
		{
		}

		friend std::ostream & operator<<( std::ostream & os, verbose_diagnostic_info const & x )
		{
			os << "leaf::verbose_diagnostic_info for ";
			x.print(os);
			os << ":\n";
			x.print_(os, x.tup_, x.err_id_.value());
			if( x.e_ui_ )
				x.e_ui_->print(os);
			return os;
		}
	};

#else

	class diagnostic_info: public error_info
	{
	public:

		BOOST_LEAF_CONSTEXPR diagnostic_info( error_info const & ei ) noexcept:
			error_info(ei)
		{
		}

		friend std::ostream & operator<<( std::ostream & os, diagnostic_info const & x )
		{
			os <<
				"leaf::diagnostic_info requires #define BOOST_LEAF_DIAGNOSTICS 1\n"
				"leaf::error_info: ";
			x.print(os);
			return os << '\n';
		}
	};

	class verbose_diagnostic_info: public error_info
	{
	public:

		BOOST_LEAF_CONSTEXPR verbose_diagnostic_info( error_info const & ei ) noexcept:
			error_info(ei)
		{
		}

		friend std::ostream & operator<<( std::ostream & os, verbose_diagnostic_info const & x )
		{
			os <<
				"leaf::verbose_diagnostic_info requires #define BOOST_LEAF_DIAGNOSTICS 1\n"
				"leaf::error_info: ";
			x.print(os);
			return os << '\n';
		}
	};

#endif

	////////////////////////////////////////

	namespace leaf_detail
	{
		template <class T, class... List>
		struct type_index;

		template <class T, class... Cdr>
		struct type_index<T, T, Cdr...>
		{
			static const int value = 0;
		};

		template <class T, class Car, class... Cdr>
		struct type_index<T, Car, Cdr...>
		{
			static const int value = 1 + type_index<T,Cdr...>::value;
		};

		template <class T, class Tuple>
		struct tuple_type_index;

		template <class T, class... TupleTypes>
		struct tuple_type_index<T,std::tuple<TupleTypes...>>
		{
			static const int value = type_index<T,TupleTypes...>::value;
		};

		template <class E, bool=std::is_base_of<std::exception, E>::value>
		struct peek_exception;

		template <class E>
		struct peek_exception<E, true>
		{
			BOOST_LEAF_CONSTEXPR static E * peek( error_info const & ei ) noexcept
			{
				return ei.exception_caught() ? dynamic_cast<E *>(ei.exception()) : 0;
			}
		};

		template <class E>
		struct peek_exception<E, false>
		{
			BOOST_LEAF_CONSTEXPR static E * peek( error_info const & ) noexcept
			{
				return 0;
			}
		};

		template <class E, class SlotsTuple>
		BOOST_LEAF_CONSTEXPR inline E const * peek( SlotsTuple const & tup, error_info const & ei ) noexcept
		{
			if( error_id err = ei.error() )
				if( E const * e = std::get<tuple_type_index<slot<E>,SlotsTuple>::value>(tup).has_value(err.value()) )
					return e;
				else
					return peek_exception<E const>::peek(ei);
			else
				return 0;
		}

		template <class E, class SlotsTuple>
		BOOST_LEAF_CONSTEXPR inline E * peek( SlotsTuple & tup, error_info const & ei ) noexcept
		{
			if( error_id err = ei.error() )
				if( E * e = std::get<tuple_type_index<slot<E>,SlotsTuple>::value>(tup).has_value(err.value()) )
					return e;
				else
					return peek_exception<E>::peek(ei);
			else
				return 0;
		}
	}

	////////////////////////////////////////

	template <class E, class ErrorConditionEnum = E>
	struct condition
	{
	};

	namespace leaf_detail
	{
		template <class T> using has_member_value_impl = decltype( std::declval<T>().value );
		template <class T> using has_member_value_fn_impl = decltype( std::declval<T>().value() );

		template <class T>
		struct has_member_value
		{
			enum { value = leaf_detail_mp11::mp_valid<has_member_value_impl, T>::value || leaf_detail_mp11::mp_valid<has_member_value_fn_impl, T>::value };
		};

		template <class Enum, bool = has_member_value<Enum>::value>
		struct match_traits;

		template <class Enum>
		struct match_traits<Enum, false>
		{
			using enum_type = Enum;
			using error_type = Enum;
			using value_type = Enum;

			BOOST_LEAF_CONSTEXPR static value_type const & value( error_type const & x )
			{
				return x;
			}
		};

		template <class E, bool = leaf_detail_mp11::mp_valid<has_member_value_fn_impl, E>::value>
		struct match_traits_value;

		template <class E>
		struct match_traits_value<E, false>
		{
			using enum_type = decltype(std::declval<E>().value);
			using error_type = E;
			using value_type = enum_type;

			BOOST_LEAF_CONSTEXPR static value_type const & value( error_type const & x )
			{
				return x.value;
			}
		};

		template <class E>
		struct match_traits_value<E, true>
		{
			using enum_type = decltype(std::declval<E>().value());
			using error_type = E;
			using value_type = enum_type;

			BOOST_LEAF_CONSTEXPR static value_type value( error_type const & x )
			{
				return x.value();
			}
		};

		template <class E>
		struct match_traits<E, true>: match_traits_value<E>
		{
		};

		template <class ErrorConditionEnum>
		struct match_traits<condition<ErrorConditionEnum, ErrorConditionEnum>, false>
		{
			static_assert(std::is_error_condition_enum<ErrorConditionEnum>::value, "If leaf::condition is instantiated with one type, that type must be a std::error_condition_enum");

			using enum_type = ErrorConditionEnum;
			using error_type = std::error_code;
			using value_type = std::error_code;

			BOOST_LEAF_CONSTEXPR static value_type const & value( error_type const & x )
			{
				return x;
			}
		};

		template <class E, class ErrorConditionEnum>
		struct match_traits<condition<E, ErrorConditionEnum>, false>
		{
			static_assert(std::is_error_condition_enum<ErrorConditionEnum>::value, "If leaf::condition is instantiated with two types, the second one must be a std::error_condition_enum");

			using enum_type = ErrorConditionEnum;
			using error_type = E;
			using value_type = std::error_code;

			static value_type value( error_type const & x )
			{
				return x.value;
			}
		};

		template <class ValueType, class V>
		BOOST_LEAF_CONSTEXPR inline bool check_value_pack( ValueType const & x, V v ) noexcept
		{
			return x==v;
		}

		template <class ValueType, class VCar, class... VCdr>
		BOOST_LEAF_CONSTEXPR inline bool check_value_pack( ValueType const & x, VCar car, VCdr ... cdr ) noexcept
		{
			return x==car || check_value_pack(x, cdr...);
		}
	}

	template <class E, typename leaf_detail::match_traits<E>::enum_type... V>
	class match
	{
	public:
		using error_type = typename leaf_detail::match_traits<E>::error_type;
		using value_type = typename leaf_detail::match_traits<E>::value_type;

	private:
		error_type const * const err_;

	public:

		BOOST_LEAF_CONSTEXPR explicit match( error_type const * err ) noexcept:
			err_(err)
		{
		}

		BOOST_LEAF_CONSTEXPR bool operator()() const noexcept
		{
			return err_ && leaf_detail::check_value_pack(value(), V...);
		}

		BOOST_LEAF_CONSTEXPR value_type value() const noexcept
		{
			BOOST_LEAF_ASSERT(err_!=0);
			return leaf_detail::match_traits<E>::value(*err_);
		}
	};

	namespace leaf_detail
	{
		template <class E, typename match_traits<E>::enum_type... V> struct translate_type_impl<match<E,V...>> { using type = typename match_traits<E>::error_type; };
		template <class E, typename match_traits<E>::enum_type... V> struct translate_type_impl<match<E,V...> const> { static_assert(sizeof(match<E,V...>)==0, "Handlers should take match<> by value, not as match<> const"); };
		template <class E, typename match_traits<E>::enum_type... V> struct translate_type_impl<match<E,V...> const *> { static_assert(sizeof(match<E,V...>)==0, "Handlers should take match<> by value, not as match<> const *"); };
		template <class E, typename match_traits<E>::enum_type... V> struct translate_type_impl<match<E,V...> const &> { static_assert(sizeof(match<E,V...>)==0, "Handlers should take match<> by value, not as match<> const &"); };
	}

	////////////////////////////////////////

	namespace leaf_detail
	{
		template <class SlotsTuple>
		struct always_available
		{
			constexpr static bool check( SlotsTuple const &, error_info const & )
			{
				return true;
			}
		};

		template <class SlotsTuple, class T>
		struct check_one_argument
		{
			BOOST_LEAF_CONSTEXPR static bool check( SlotsTuple const & tup, error_info const & ei ) noexcept
			{
				return peek<T>(tup, ei)!=0;
			}
		};

		template <class SlotsTuple, class T>
		struct check_one_argument<SlotsTuple, T *>: always_available<SlotsTuple> { };

		template <class SlotsTuple>
		struct check_one_argument<SlotsTuple,error_info>: always_available<SlotsTuple> { };

		template <class SlotsTuple>
		struct check_one_argument<SlotsTuple,diagnostic_info>: always_available<SlotsTuple> { };

		template <class SlotsTuple>
		struct check_one_argument<SlotsTuple,verbose_diagnostic_info>: always_available<SlotsTuple> { };

		template <class SlotsTuple, class T, typename match_traits<T>::enum_type... V>
		struct check_one_argument<SlotsTuple, match<T, V...>>
		{
			BOOST_LEAF_CONSTEXPR static bool check( SlotsTuple const & tup, error_info const & ei ) noexcept
			{
				using error_type = typename match<T, V...>::error_type;
				return match<T, V...>(peek<error_type>(tup, ei))();
			}
		};

		template <class SlotsTuple, class... List>
		struct check_arguments;

		template <class SlotsTuple, class Car, class... Cdr>
		struct check_arguments<SlotsTuple, Car, Cdr...>
		{
			BOOST_LEAF_CONSTEXPR static bool check( SlotsTuple const & tup, error_info const & ei ) noexcept
			{
				return check_one_argument<SlotsTuple,Car>::check(tup,ei) && check_arguments<SlotsTuple,Cdr...>::check(tup,ei);
			}
		};

		template <class SlotsTuple>
		struct check_arguments<SlotsTuple>
		{
			constexpr static bool check( SlotsTuple const &, error_info const & ) noexcept
			{
				return true;
			}
		};
	}

	////////////////////////////////////////

	namespace leaf_detail
	{
		template <class T>
		struct get_one_argument
		{
			template <class SlotsTuple>
			BOOST_LEAF_CONSTEXPR static T const & get( SlotsTuple const & tup, error_info const & ei ) noexcept
			{
				T const * arg = peek<T>(tup, ei);
				BOOST_LEAF_ASSERT(arg!=0);
				return *arg;
			}

			template <class SlotsTuple>
			BOOST_LEAF_CONSTEXPR static T & get( SlotsTuple & tup, error_info const & ei ) noexcept
			{
				T * arg = peek<T>(tup, ei);
				BOOST_LEAF_ASSERT(arg!=0);
				return *arg;
			}
		};

		template <class T>
		struct get_one_argument<T *>
		{
			template <class SlotsTuple>
			BOOST_LEAF_CONSTEXPR static T * get( SlotsTuple & tup, error_info const & ei ) noexcept
			{
				return peek<T>(tup, ei);
			}
		};

		template <class T>
		struct get_one_argument<T const *>
		{
			template <class SlotsTuple>
			BOOST_LEAF_CONSTEXPR static T const * get( SlotsTuple const & tup, error_info const & ei ) noexcept
			{
				return peek<T>(tup, ei);
			}
		};

		template <>
		struct get_one_argument<error_info>
		{
			template <class SlotsTuple>
			BOOST_LEAF_CONSTEXPR static error_info const & get( SlotsTuple const &, error_info const & ei ) noexcept
			{
				return ei;
			}
		};

#if BOOST_LEAF_DIAGNOSTICS

		template <>
		struct get_one_argument<diagnostic_info>
		{
			template <class SlotsTuple>
			BOOST_LEAF_CONSTEXPR static diagnostic_info get( SlotsTuple const & tup, error_info const & ei ) noexcept
			{
				return diagnostic_info(ei, peek<e_unexpected_count>(tup, ei), tup);
			}
		};

		template <>
		struct get_one_argument<verbose_diagnostic_info>
		{
			template <class SlotsTuple>
			BOOST_LEAF_CONSTEXPR static verbose_diagnostic_info get( SlotsTuple const & tup, error_info const & ei ) noexcept
			{
				return verbose_diagnostic_info(ei, peek<e_unexpected_info>(tup, ei), tup);
			}
		};

#else

		template <>
		struct get_one_argument<diagnostic_info>
		{
			template <class SlotsTuple>
			BOOST_LEAF_CONSTEXPR static diagnostic_info get( SlotsTuple const & tup, error_info const & ei ) noexcept
			{
				return diagnostic_info(ei);
			}
		};

		template <>
		struct get_one_argument<verbose_diagnostic_info>
		{
			template <class SlotsTuple>
			BOOST_LEAF_CONSTEXPR static verbose_diagnostic_info get( SlotsTuple const & tup, error_info const & ei ) noexcept
			{
				return verbose_diagnostic_info(ei);
			}
		};

#endif

		template <class T, typename match_traits<T>::enum_type... V>
		struct get_one_argument<match<T, V...>>
		{
			template <class SlotsTuple>
			BOOST_LEAF_CONSTEXPR static match<T, V...> get( SlotsTuple const & tup, error_info const & ei ) noexcept
			{
				using error_type = typename match<T, V...>::error_type;
				return match<T, V...>(peek<error_type>(tup, ei));
			}
		};
	}

	////////////////////////////////////////

	namespace leaf_detail
	{
		template <class T> struct argument_matches_any_error: std::false_type { };
		template <class T> struct argument_matches_any_error<T *>: std::true_type { };
		template <> struct argument_matches_any_error<error_info const &>: std::true_type { };
		template <> struct argument_matches_any_error<diagnostic_info const &>: std::true_type { };
		template <> struct argument_matches_any_error<verbose_diagnostic_info const &>: std::true_type { };

		template <class>
		struct handler_matches_any_error: std::false_type
		{
		};

		template <template<class...> class L, class Car, class... Cdr>
		struct handler_matches_any_error<L<Car,Cdr...>>
		{
			constexpr static bool value = argument_matches_any_error<Car>::value && handler_matches_any_error<L<Cdr...>>::value;
		};

		template <template<class...> class L>
		struct handler_matches_any_error<L<>>: std::true_type
		{
		};
	}

	////////////////////////////////////////

	namespace leaf_detail
	{
		template <class Tup, class... T>
		BOOST_LEAF_CONSTEXPR inline bool check_handler_( Tup & e_objects, error_info const & ei, leaf_detail_mp11::mp_list<T...> ) noexcept
		{
			return check_arguments<Tup,typename std::remove_cv<typename std::remove_reference<T>::type>::type...>::check(e_objects, ei);
		}

		template <class R, class F, bool IsResult = is_result_type<R>::value, class FReturnType = fn_return_type<F>>
		struct handler_caller
		{
			template <class Tup, class... T>
			BOOST_LEAF_CONSTEXPR static R call( Tup & e_objects, error_info const & ei, F && f, leaf_detail_mp11::mp_list<T...> )
			{
				return std::forward<F>(f)( get_one_argument<typename std::remove_cv<typename std::remove_reference<T>::type>::type>::get(e_objects, ei)... );
			}
		};

		template <template <class...> class Result, class... E, class F>
		struct handler_caller<Result<void, E...>, F, true, void>
		{
			using R = Result<void, E...>;

			template <class Tup,class... T>
			BOOST_LEAF_CONSTEXPR static R call( Tup & e_objects, error_info const & ei, F && f, leaf_detail_mp11::mp_list<T...> )
			{
				std::forward<F>(f)( get_one_argument<typename std::remove_cv<typename std::remove_reference<T>::type>::type>::get(e_objects, ei)... );
				return { };
			}
		};

		template <class T>
		struct is_tuple: std::false_type { };

		template <class... T>
		struct is_tuple<std::tuple<T...>>: std::true_type { };

		template <class... T>
		struct is_tuple<std::tuple<T...> &>: std::true_type { };

		template <class R, class Tup, class H>
		BOOST_LEAF_CONSTEXPR inline typename std::enable_if<!is_tuple<H>::value, R>::type handle_error_( Tup & tup, error_info const & ei, H && h )
		{
			static_assert( handler_matches_any_error<fn_mp_args<H>>::value, "The last handler passed to handle_all must match any error." );
			return handler_caller<R, H>::call( tup, ei, std::forward<H>(h), fn_mp_args<H>{ } );
		}

		template <class R, class Tup, class Car, class... Cdr>
		BOOST_LEAF_CONSTEXPR inline typename std::enable_if<!is_tuple<Car>::value, R>::type handle_error_( Tup & tup, error_info const & ei, Car && car, Cdr && ... cdr )
		{
			if( handler_matches_any_error<fn_mp_args<Car>>::value || check_handler_( tup, ei, fn_mp_args<Car>{ } ) )
				return handler_caller<R, Car>::call( tup, ei, std::forward<Car>(car), fn_mp_args<Car>{ } );
			else
				return handle_error_<R>( tup, ei, std::forward<Cdr>(cdr)...);
		}

		template <class R, class Tup, class HTup, size_t ... I>
		BOOST_LEAF_CONSTEXPR inline R handle_error_tuple_( Tup & tup, error_info const & ei, leaf_detail_mp11::index_sequence<I...>, HTup && htup )
		{
			return handle_error_<R>(tup, ei, std::get<I>(std::forward<HTup>(htup))...);
		}

		template <class R, class Tup, class HTup, class... Cdr, size_t ... I>
		BOOST_LEAF_CONSTEXPR inline R handle_error_tuple_( Tup & tup, error_info const & ei, leaf_detail_mp11::index_sequence<I...>, HTup && htup, Cdr && ... cdr )
		{
			return handle_error_<R>(tup, ei, std::get<I>(std::forward<HTup>(htup))..., std::forward<Cdr>(cdr)...);
		}

		template <class R, class Tup, class H>
		BOOST_LEAF_CONSTEXPR inline typename std::enable_if<is_tuple<H>::value, R>::type handle_error_( Tup & tup, error_info const & ei, H && h )
		{
			return handle_error_tuple_<R>(
				tup,
				ei,
				leaf_detail_mp11::make_index_sequence<std::tuple_size<typename std::decay<H>::type>::value>(),
				std::forward<H>(h));
		}

		template <class R, class Tup, class Car, class... Cdr>
		BOOST_LEAF_CONSTEXPR inline typename std::enable_if<is_tuple<Car>::value, R>::type handle_error_( Tup & tup, error_info const & ei, Car && car, Cdr && ... cdr )
		{
			return handle_error_tuple_<R>(
				tup,
				ei,
				leaf_detail_mp11::make_index_sequence<std::tuple_size<typename std::decay<Car>::type>::value>(),
				std::forward<Car>(car),
				std::forward<Cdr>(cdr)...);
		}
	}

	////////////////////////////////////////

	namespace leaf_detail
	{
		template <class T, template <class...> class R, class... E>
		struct add_result
		{
			using type = R<T, E...>;
		};

		template <class T, template <class...> class R, class... E>
		struct add_result<R<T, E...>, R, E...>
		{
			using type = R<T, E...>;
		};

		template <class... T>
		struct handler_pack_return_impl;

		template <class T>
		struct handler_pack_return_impl<T>
		{
			using type = T;
		};

		template <class Car, class... Cdr>
		struct handler_pack_return_impl<Car, Car, Cdr...>
		{
			using type = typename handler_pack_return_impl<Car, Cdr...>::type;
		};

		template <template <class...> class R, class... E, class Car, class... Cdr>
		struct handler_pack_return_impl<R<Car,E...>, Car, Cdr...>
		{
			using type = typename handler_pack_return_impl<R<Car,E...>, typename add_result<Cdr,R,E...>::type...>::type;
		};

		template <template <class...> class R, class... E, class Car, class... Cdr>
		struct handler_pack_return_impl<Car, R<Car,E...>, Cdr...>
		{
			using type = typename handler_pack_return_impl<R<Car,E...>, typename add_result<Cdr,R,E...>::type...>::type;
		};

		template <class... H>
		using handler_pack_return = typename handler_pack_return_impl<typename std::decay<fn_return_type<H>>::type...>::type;

		template <class... H>
		struct handler_result
		{
			using R = handler_pack_return<H...>;

			R r;

			BOOST_LEAF_CONSTEXPR R get() noexcept
			{
				return std::move(r);
			}
		};

		template <class... H>
		struct handler_result_void
		{
			BOOST_LEAF_CONSTEXPR void get() noexcept
			{
			}
		};
	}

	////////////////////////////////////////

	namespace leaf_detail
	{
		template <class... E>
		template <class R, class... H>
		BOOST_LEAF_CONSTEXPR inline R context_base<E...>::handle_error( error_id id, H && ... h ) const
		{
			BOOST_LEAF_ASSERT(!is_active());
			return handle_error_<R>(tup(), error_info(id), std::forward<H>(h)...);
		}

		template <class... E>
		template <class R, class... H>
		BOOST_LEAF_CONSTEXPR inline R context_base<E...>::handle_error( error_id id, H && ... h )
		{
			BOOST_LEAF_ASSERT(!is_active());
			return handle_error_<R>(tup(), error_info(id), std::forward<H>(h)...);
		}
	}

	////////////////////////////////////////

	namespace leaf_detail
	{
		template <class... E>
		class nocatch_context: public context_base<E...>
		{
		public:

			template <class TryBlock, class... H>
			BOOST_LEAF_CONSTEXPR BOOST_LEAF_ALWAYS_INLINE typename std::decay<decltype(std::declval<TryBlock>()().value())>::type try_handle_all( TryBlock && try_block, H && ... h )
			{
				using namespace leaf_detail;
				static_assert(is_result_type<decltype(std::declval<TryBlock>()())>::value, "The return type of the try_block passed to a try_handle_all function must be registered with leaf::is_result_type");
				auto active_context = activate_context(*this);
				if( auto r = std::forward<TryBlock>(try_block)() )
					return r.value();
				else
				{
					error_id id = r.error();
					this->deactivate();
					using R = typename std::decay<decltype(std::declval<TryBlock>()().value())>::type;
					return this->template handle_error<R>(std::move(id), std::forward<H>(h)...);
				}
			}

			template <class TryBlock, class... H>
			BOOST_LEAF_CONSTEXPR BOOST_LEAF_ALWAYS_INLINE typename std::decay<decltype(std::declval<TryBlock>()())>::type try_handle_some( TryBlock && try_block, H && ... h )
			{
				using namespace leaf_detail;
				static_assert(is_result_type<decltype(std::declval<TryBlock>()())>::value, "The return type of the try_block passed to a try_handle_some function must be registered with leaf::is_result_type");
				auto active_context = activate_context(*this);
				if( auto r = std::forward<TryBlock>(try_block)() )
					return r;
				else
				{
					error_id id = r.error();
					this->deactivate();
					using R = typename std::decay<decltype(std::declval<TryBlock>()())>::type;
					auto rr = this->template handle_error<R>(std::move(id), std::forward<H>(h)..., [&r]()->R { return std::move(r); });
					if( !rr )
						this->propagate();
					return rr;
				}
			}
		};
	}

	////////////////////////////////////////

	template <class TryBlock, class... H>
	BOOST_LEAF_CONSTEXPR inline typename std::decay<decltype(std::declval<TryBlock>()().value())>::type try_handle_all( TryBlock && try_block, H && ... h )
	{
		// Creating a named temp on purpose, to avoid C++11 and C++14 zero-initializing the context.
		context_type_from_handlers<H...> c;
		return c.try_handle_all( std::forward<TryBlock>(try_block), std::forward<H>(h)... );
	}

	template <class TryBlock, class... H>
	BOOST_LEAF_CONSTEXPR inline typename std::decay<decltype(std::declval<TryBlock>()())>::type try_handle_some( TryBlock && try_block, H && ... h )
	{
		// Creating a named temp on purpose, to avoid C++11 and C++14 zero-initializing the context.
		context_type_from_handlers<H...> c;
		return c.try_handle_some( std::forward<TryBlock>(try_block), std::forward<H>(h)... );
	}

} }

#endif
// <<< #include <boost/leaf/handle_error.hpp>
#line 16 "../../include/boost/leaf/detail/all.hpp"
#ifndef BOOST_LEAF_NO_EXCEPTIONS
// >>> #	include <boost/leaf/handle_exception.hpp>
#line 1 "boost/leaf/handle_exception.hpp"
#ifndef BOOST_LEAF_HANDLE_EXCEPTION_HPP_INCLUDED
#define BOOST_LEAF_HANDLE_EXCEPTION_HPP_INCLUDED

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

#ifdef BOOST_LEAF_NO_EXCEPTIONS
#	error This header requires exception handling
#endif

// >>> #include <boost/leaf/detail/demangle.hpp>
#line 1 "boost/leaf/detail/demangle.hpp"
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
// <<< #include <boost/leaf/detail/demangle.hpp>
#line 25 "boost/leaf/handle_exception.hpp"

namespace boost { namespace leaf {

	namespace leaf_detail
	{
		template <class... E>
		class catch_context: public context_base<E...>
		{
		public:

			template <class TryBlock, class... H>
			BOOST_LEAF_CONSTEXPR inline typename std::decay<decltype(std::declval<TryBlock>()().value())>::type try_handle_all( TryBlock && try_block, H && ... h )
			{
				using namespace leaf_detail;
				static_assert(is_result_type<decltype(std::declval<TryBlock>()())>::value, "The return type of the try_block passed to a try_handle_all function must be registered with leaf::is_result_type");
				auto active_context = activate_context(*this);
				if(	auto r = this->try_catch_(
						[&]
						{
							return std::forward<TryBlock>(try_block)();
						},
						std::forward<H>(h)...) )
					return r.value();
				else
				{
					error_id id = r.error();
					this->deactivate();
					using R = typename std::decay<decltype(std::declval<TryBlock>()().value())>::type;
					return this->template handle_error<R>(std::move(id), std::forward<H>(h)...);
				}
			}

			template <class TryBlock, class... H>
			BOOST_LEAF_CONSTEXPR inline typename std::decay<decltype(std::declval<TryBlock>()())>::type try_handle_some( TryBlock && try_block, H && ... h )
			{
				using namespace leaf_detail;
				static_assert(is_result_type<decltype(std::declval<TryBlock>()())>::value, "The return type of the try_block passed to a try_handle_some function must be registered with leaf::is_result_type");
				auto active_context = activate_context(*this);
				if(	auto r = this->try_catch_(
						[&]
						{
							return std::forward<TryBlock>(try_block)();
						},
						std::forward<H>(h)...) )
					return r;
				else
				{
					error_id id = r.error();
					this->deactivate();
					using R = typename std::decay<decltype(std::declval<TryBlock>()())>::type;
					auto rr = this->template handle_error<R>(std::move(id), std::forward<H>(h)..., [&r]()->R { return std::move(r); });
					if( !rr )
						this->propagate();
					return rr;
				}
			}
		};

		template <class Ex>
		BOOST_LEAF_CONSTEXPR inline bool check_exception_pack( std::exception const * ex, Ex const * ) noexcept
		{
			return dynamic_cast<Ex const *>(ex)!=0;
		}

		template <class Ex, class... ExRest>
		BOOST_LEAF_CONSTEXPR inline bool check_exception_pack( std::exception const * ex, Ex const *, ExRest const * ... ex_rest ) noexcept
		{
			return dynamic_cast<Ex const *>(ex)!=0 || check_exception_pack(ex, ex_rest...);
		}

		BOOST_LEAF_CONSTEXPR inline bool check_exception_pack( std::exception const * )
		{
			return true;
		}
	}

	template <class... Ex>
	class catch_
	{
		std::exception const * const value_;

	public:

		BOOST_LEAF_CONSTEXPR explicit catch_( std::exception const * value ) noexcept:
			value_(value)
		{
		}

		BOOST_LEAF_CONSTEXPR bool operator()() const noexcept
		{
			return value_ && leaf_detail::check_exception_pack(value_,static_cast<Ex const *>(0)...);
		}

		BOOST_LEAF_CONSTEXPR std::exception const & value() const noexcept
		{
			BOOST_LEAF_ASSERT(value_!=0);
			return *value_;
		}
	};

	template <class Ex>
	class catch_<Ex>
	{
		Ex const * const value_;

	public:

		BOOST_LEAF_CONSTEXPR explicit catch_( std::exception const * value ) noexcept:
			value_(dynamic_cast<Ex const *>(value))
		{
		}

		BOOST_LEAF_CONSTEXPR bool operator()() const noexcept
		{
			return this->value_!=0;
		}

		BOOST_LEAF_CONSTEXPR Ex const & value() const noexcept
		{
			BOOST_LEAF_ASSERT(this->value_!=0);
			return *this->value_;
		}
	};

	namespace leaf_detail
	{
		template <class... Exceptions> struct translate_type_impl<catch_<Exceptions...>> { using type = void; };
		template <class... Exceptions> struct translate_type_impl<catch_<Exceptions...> const>;
		template <class... Exceptions> struct translate_type_impl<catch_<Exceptions...> const *> { static_assert(sizeof(catch_<Exceptions...>)==0, "Handlers should take catch_<> by value, not as catch_<> const *"); };
		template <class... Exceptions> struct translate_type_impl<catch_<Exceptions...> const &> { static_assert(sizeof(catch_<Exceptions...>)==0, "Handlers should take catch_<> by value, not as catch_<> const &"); };

		template <class SlotsTuple, class... Ex>
		struct check_one_argument<SlotsTuple,catch_<Ex...>>
		{
			BOOST_LEAF_CONSTEXPR static bool check( SlotsTuple const &, error_info const & ei ) noexcept
			{
				if( ei.exception_caught() )
					return catch_<Ex...>(ei.exception())();
				else
					return false;
			}
		};

		template <class... Ex>
		struct get_one_argument<catch_<Ex...>>
		{
			template <class SlotsTuple>
			BOOST_LEAF_CONSTEXPR static catch_<Ex...> get( SlotsTuple const &, error_info const & ei ) noexcept
			{
				std::exception const * ex = ei.exception();
				BOOST_LEAF_ASSERT(ex!=0);
				return catch_<Ex...>(ex);
			}
		};
	}

	////////////////////////////////////////

	namespace leaf_detail
	{
		inline void exception_info_::print( std::ostream & os ) const
		{
			if( ex_ )
			{
				os <<
					"\nException dynamic type: " << leaf_detail::demangle(typeid(*ex_).name()) <<
					"\nstd::exception::what(): " << ex_->what();
			}
			else
				os << "\nUnknown exception type (not a std::exception)";
		}

		BOOST_LEAF_CONSTEXPR inline exception_info_::exception_info_( std::exception * ex ) noexcept:
			exception_info_base(ex)
		{
		}

		template <class... E>
		template <class TryBlock, class... H>
		inline decltype(std::declval<TryBlock>()()) context_base<E...>::try_catch_( TryBlock && try_block, H && ... h )
		{
			using namespace leaf_detail;
			BOOST_LEAF_ASSERT(is_active());
			using R = decltype(std::declval<TryBlock>()());
			try
			{
				return std::forward<TryBlock>(try_block)();
			}
			catch( capturing_exception const & cap )
			{
				try
				{
					cap.unload_and_rethrow_original_exception();
				}
				catch( std::exception & ex )
				{
					deactivate();
					return leaf_detail::handle_error_<R>(this->tup(), error_info(exception_info_(&ex)), std::forward<H>(h)...,
						[]() -> R { throw; } );
				}
				catch(...)
				{
					deactivate();
					return leaf_detail::handle_error_<R>(this->tup(), error_info(exception_info_(0)), std::forward<H>(h)...,
						[]() -> R { throw; } );
				}
			}
			catch( std::exception & ex )
			{
				deactivate();
				return leaf_detail::handle_error_<R>(this->tup(), error_info(exception_info_(&ex)), std::forward<H>(h)...,
					[]() -> R { throw; } );
			}
			catch(...)
			{
				deactivate();
				return leaf_detail::handle_error_<R>(this->tup(), error_info(exception_info_(0)), std::forward<H>(h)...,
					[]() -> R { throw; } );
			}
		}
	}

	////////////////////////////////////////

	namespace leaf_detail
	{
		inline error_id unpack_error_id( std::exception const * ex ) noexcept
		{
			if( std::system_error const * se = dynamic_cast<std::system_error const *>(ex) )
				return error_id(se->code());
			else if( std::error_code const * ec = dynamic_cast<std::error_code const *>(ex) )
				return error_id(*ec);
			else if( error_id const * err_id = dynamic_cast<error_id const *>(ex) )
				return *err_id;
			else
				return current_error();
		}

		BOOST_LEAF_CONSTEXPR inline exception_info_base::exception_info_base( std::exception * ex ) noexcept:
			ex_(ex)
		{
			BOOST_LEAF_ASSERT(!dynamic_cast<capturing_exception const *>(ex_));
		}

		inline exception_info_base::~exception_info_base() noexcept
		{
		}
	}

	inline error_info::error_info( leaf_detail::exception_info_ const & xi ) noexcept:
		xi_(&xi),
		err_id_(leaf_detail::unpack_error_id(xi_->ex_))
	{
	}

	////////////////////////////////////////

	template <class TryBlock, class... H>
	BOOST_LEAF_CONSTEXPR inline decltype(std::declval<TryBlock>()()) try_catch( TryBlock && try_block, H && ... h )
	{
		using namespace leaf_detail;
		context_type_from_handlers<H...> ctx;
		auto active_context = activate_context(ctx);
		return ctx.try_catch_(
			[&]
			{
				return std::forward<TryBlock>(try_block)();
			},
			std::forward<H>(h)...);
	}

} }

#endif
// <<< #	include <boost/leaf/handle_exception.hpp>
#line 18 "../../include/boost/leaf/detail/all.hpp"
#endif
// >>> #include <boost/leaf/result.hpp>
#line 1 "boost/leaf/result.hpp"
#ifndef BOOST_LEAF_RESULT_HPP_INCLUDED
#define BOOST_LEAF_RESULT_HPP_INCLUDED

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

#include <memory>
#include <climits>

namespace boost { namespace leaf {

	class bad_result:
		public std::exception,
		public error_id
	{
		char const * what() const noexcept final override
		{
			return "boost::leaf::bad_result";
		}

	public:

		explicit bad_result( error_id id ) noexcept:
			error_id(id)
		{
			BOOST_LEAF_ASSERT(value());
		}
	};

	////////////////////////////////////////

	namespace leaf_detail
	{
		class result_discriminant
		{
			unsigned state_;

		public:

			enum kind_t
			{
				no_error = 0,
				err_id = 1,
				ctx_ptr = 2,
				val = 3
			};

			BOOST_LEAF_CONSTEXPR explicit result_discriminant( error_id id ) noexcept:
				state_(id.value())
			{
				BOOST_LEAF_ASSERT(state_==0 || (state_&3)==1);
			}

			struct kind_val { };
			BOOST_LEAF_CONSTEXPR explicit result_discriminant( kind_val ) noexcept:
				state_(val)
			{
			}

			struct kind_ctx_ptr { };
			BOOST_LEAF_CONSTEXPR explicit result_discriminant( kind_ctx_ptr ) noexcept:
				state_(ctx_ptr)
			{
			}

			BOOST_LEAF_CONSTEXPR kind_t kind() const noexcept
			{
				return kind_t(state_&3);
			}

			BOOST_LEAF_CONSTEXPR error_id get_error_id() const noexcept
			{
				BOOST_LEAF_ASSERT(kind()==no_error || kind()==err_id);
				return leaf_detail::make_error_id(state_);
			}
		};
	}

	////////////////////////////////////////

	template <class T>
	class result
	{
		template <class U>
		friend class result;

		using result_discriminant = leaf_detail::result_discriminant;

		struct error_result
		{
			error_result( error_result && ) = default;
			error_result( error_result const & ) = delete;
			error_result & operator=( error_result const & ) = delete;

			result & r_;

			BOOST_LEAF_CONSTEXPR error_result( result & r ) noexcept:
				r_(r)
			{
			}

			template <class U>
			BOOST_LEAF_CONSTEXPR operator result<U>() noexcept
			{
				switch(r_.what_.kind())
				{
				case result_discriminant::val:
					return result<U>(error_id());
				case result_discriminant::ctx_ptr:
					return result<U>(std::move(r_.ctx_));
				default:
					return result<U>(std::move(r_.what_));
				}
			}

			BOOST_LEAF_CONSTEXPR operator error_id() noexcept
			{
				switch(r_.what_.kind())
				{
				case result_discriminant::val:
					return error_id();
				case result_discriminant::ctx_ptr:
				{
					error_id captured_id = r_.ctx_->propagate_captured_errors();
					leaf_detail::id_factory<>::current_id = captured_id.value();
					return captured_id;
				}
				default:
					return r_.what_.get_error_id();
				}
			}
		};

		union
		{
			T value_;
			context_ptr ctx_;
		};

		result_discriminant what_;

		BOOST_LEAF_CONSTEXPR void destroy() const noexcept
		{
			switch(this->what_.kind())
			{
			case result_discriminant::val:
				value_.~T();
				break;
			case result_discriminant::ctx_ptr:
				BOOST_LEAF_ASSERT(!ctx_ || ctx_->captured_id_);
				ctx_.~context_ptr();
			default:
				break;
			}
		}

		template <class U>
		BOOST_LEAF_CONSTEXPR result_discriminant move_from( result<U> && x ) noexcept
		{
			auto x_what = x.what_;
			switch(x_what.kind())
			{
			case result_discriminant::val:
				(void) new(&value_) T(std::move(x.value_));
				break;
			case result_discriminant::ctx_ptr:
				BOOST_LEAF_ASSERT(!x.ctx_ || x.ctx_->captured_id_);
				(void) new(&ctx_) context_ptr(std::move(x.ctx_));
			default:
				break;
			}
			return x_what;
		}

		BOOST_LEAF_CONSTEXPR result( result_discriminant && what ) noexcept:
			what_(std::move(what))
		{
			BOOST_LEAF_ASSERT(what_.kind()==result_discriminant::err_id || what_.kind()==result_discriminant::no_error);
		}

		BOOST_LEAF_CONSTEXPR error_id get_error_id() const noexcept
		{
			BOOST_LEAF_ASSERT(what_.kind()!=result_discriminant::val);
			return what_.kind()==result_discriminant::ctx_ptr ? ctx_->captured_id_ : what_.get_error_id();
		}

	public:

		using value_type = T;

		BOOST_LEAF_CONSTEXPR result( result && x ) noexcept:
			what_(move_from(std::move(x)))
		{
		}

		template <class U>
		BOOST_LEAF_CONSTEXPR result( result<U> && x ) noexcept:
			what_(move_from(std::move(x)))

		{
		}

		BOOST_LEAF_CONSTEXPR result():
			value_(T()),
			what_(result_discriminant::kind_val{})
		{
		}

		BOOST_LEAF_CONSTEXPR result( T && v ) noexcept:
			value_(std::move(v)),
			what_(result_discriminant::kind_val{})
		{
		}

		BOOST_LEAF_CONSTEXPR result( T const & v ):
			value_(v),
			what_(result_discriminant::kind_val{})
		{
		}

		BOOST_LEAF_CONSTEXPR result( error_id err ) noexcept:
			what_(err)
		{
		}

		BOOST_LEAF_CONSTEXPR result( std::error_code const & ec ) noexcept:
			what_(error_id(ec))
		{
		}

		BOOST_LEAF_CONSTEXPR result( context_ptr && ctx ) noexcept:
			ctx_(std::move(ctx)),
			what_(result_discriminant::kind_ctx_ptr{})
		{
		}

		~result() noexcept
		{
			destroy();
		}

		BOOST_LEAF_CONSTEXPR result & operator=( result && x ) noexcept
		{
			destroy();
			what_ = move_from(std::move(x));
			return *this;
		}

		template <class U>
		BOOST_LEAF_CONSTEXPR result & operator=( result<U> && x ) noexcept
		{
			destroy();
			what_ = move_from(std::move(x));
			return *this;
		}

		BOOST_LEAF_CONSTEXPR explicit operator bool() const noexcept
		{
			return what_.kind() == result_discriminant::val;
		}

		BOOST_LEAF_CONSTEXPR T const & value() const
		{
			if( what_.kind() == result_discriminant::val )
				return value_;
			else
				::boost::leaf::throw_exception(bad_result(get_error_id()));
		}

		BOOST_LEAF_CONSTEXPR T & value()
		{
			if( what_.kind() == result_discriminant::val )
				return value_;
			else
				::boost::leaf::throw_exception(bad_result(get_error_id()));
		}

		BOOST_LEAF_CONSTEXPR T const & operator*() const
		{
			return value();
		}

		BOOST_LEAF_CONSTEXPR T & operator*()
		{
			return value();
		}

		BOOST_LEAF_CONSTEXPR T const * operator->() const
		{
			return &value();
		}

		BOOST_LEAF_CONSTEXPR T * operator->()
		{
			return &value();
		}

		BOOST_LEAF_CONSTEXPR error_result error() noexcept
		{
			return error_result{*this};
		}

		template <class... Item>
		BOOST_LEAF_CONSTEXPR error_id load( Item && ... item ) noexcept
		{
			return error_id(error()).load(std::forward<Item>(item)...);
		}
	};

	////////////////////////////////////////

	namespace leaf_detail
	{
		struct void_ { };
	}

	template <>
	class result<void>:
		result<leaf_detail::void_>
	{
		using result_discriminant = leaf_detail::result_discriminant;
		using void_ = leaf_detail::void_;
		using base = result<void_>;

		template <class U>
		friend class result;

		BOOST_LEAF_CONSTEXPR result( result_discriminant && what ) noexcept:
			base(std::move(what))
		{
		}

	public:

		using value_type = void;

		BOOST_LEAF_CONSTEXPR result( result && x ) noexcept:
			base(std::move(x))
		{
		}

		BOOST_LEAF_CONSTEXPR result() noexcept
		{
		}

		BOOST_LEAF_CONSTEXPR result( error_id err ) noexcept:
			base(err)
		{
		}

		BOOST_LEAF_CONSTEXPR result( std::error_code const & ec ) noexcept:
			base(ec)
		{
		}

		BOOST_LEAF_CONSTEXPR result( context_ptr && ctx ) noexcept:
			base(std::move(ctx))
		{
		}

		~result() noexcept
		{
		}

		BOOST_LEAF_CONSTEXPR void value() const
		{
			(void) base::value();
		}

		using base::operator=;
		using base::operator bool;
		using base::get_error_id;
		using base::error;
		using base::load;
	};

	////////////////////////////////////////

	template <class R>
	struct is_result_type;

	template <class T>
	struct is_result_type<result<T>>: std::true_type
	{
	};
} }

#endif
// <<< #include <boost/leaf/result.hpp>
#line 21 "../../include/boost/leaf/detail/all.hpp"

#endif
