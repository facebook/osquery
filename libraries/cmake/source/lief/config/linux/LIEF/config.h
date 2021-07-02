/* Copyright 2017 - 2021 A. Guinet
 * Copyright 2017 - 2021 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LIEF_CONFIG_H_
#define LIEF_CONFIG_H_

// Main formats
/* #undef LIEF_PE_SUPPORT */
/* #undef LIEF_ELF_SUPPORT */
/* #define LIEF_MACHO_SUPPORT */
#define LIEF_ELF_SUPPORT 1
// Android formats
/* #undef LIEF_OAT_SUPPORT */
/* #undef LIEF_DEX_SUPPORT */
/* #undef LIEF_VDEX_SUPPORT */
/* #undef LIEF_ART_SUPPORT */

// LIEF options
/* #undef LIEF_JSON_SUPPORT */
/* #undef LIEF_LOGGING_SUPPORT */
/* #undef LIEF_LOGGING_DEBUG */
/* #undef LIEF_FROZEN_ENABLED */

#ifdef __cplusplus

static constexpr bool lief_pe_support      = 0;
static constexpr bool lief_elf_support     = 1;
static constexpr bool lief_macho_support   = 0;

static constexpr bool lief_oat_support     = 0;
static constexpr bool lief_dex_support     = 0;
static constexpr bool lief_vdex_support    = 0;
static constexpr bool lief_art_support     = 0;

static constexpr bool lief_json_support    = 0;
static constexpr bool lief_logging_support = 0;
static constexpr bool lief_logging_debug   = 0;
static constexpr bool lief_frozen_enabled  = 0;


#endif // __cplusplus

#endif
