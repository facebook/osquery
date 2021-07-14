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

#include <boost/leaf/context.hpp>

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
