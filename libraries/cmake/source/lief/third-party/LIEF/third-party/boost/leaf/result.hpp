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

#include <boost/leaf/exception.hpp>
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
