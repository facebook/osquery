// WARNING! leaf/preload.hpp is deprecated!
// WARNING! leaf/preload.hpp is deprecated!
// WARNING! leaf/preload.hpp is deprecated!

#ifndef BOOST_LEAF_PRELOAD_HPP_INCLUDED
#define BOOST_LEAF_PRELOAD_HPP_INCLUDED

// Copyright (c) 2018-2020 Emil Dotchevski and Reverge Studios, Inc.

// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#include <boost/leaf/on_error.hpp>

namespace boost { namespace leaf {

	template <class... Item>
	BOOST_LEAF_NODISCARD BOOST_LEAF_CONSTEXPR inline leaf_detail::preloaded<typename leaf_detail::deduce_item_type<Item>::type...> preload( Item && ... i )
	{
		return leaf_detail::preloaded<typename leaf_detail::deduce_item_type<Item>::type...>(std::forward<Item>(i)...);
	}

	template <class... Item>
	BOOST_LEAF_NODISCARD BOOST_LEAF_CONSTEXPR inline leaf_detail::preloaded<typename leaf_detail::deduce_item_type<Item>::type...> defer( Item && ... i )
	{
		return leaf_detail::preloaded<typename leaf_detail::deduce_item_type<Item>::type...>(std::forward<Item>(i)...);
	}

} }

#endif
