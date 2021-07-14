/* From llvm/Support/ELF.h */
#ifndef LIEF_ELF_STRUCTURES_H_
#define LIEF_ELF_STRUCTURES_H_

#include <cstring>

#include "LIEF/types.hpp"
#include "LIEF/ELF/enums.hpp"

namespace LIEF {
//! @brief Namespace related to the LIEF's ELF module
namespace ELF {

typedef uint32_t Elf32_Addr;
typedef uint32_t Elf32_Off;
typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Word;
typedef int32_t  Elf32_Sword;

typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef int32_t  Elf64_Sword;

typedef uint64_t Elf64_Xword;
typedef int64_t  Elf64_Sxword;


/** Object file magic string. */
static const char ElfMagic[] = {'\x7f', 'E', 'L', 'F'};

#pragma pack(push,1)

/** 32-bits ELF header */
struct Elf32_Ehdr {
  unsigned char e_ident[16];        /**< ELF Identification bytes */
  Elf32_Half    e_type;             /**< Type of file (see ET_* below) */
  Elf32_Half    e_machine;          /**< Required architecture for this file (see EM_*) */
  Elf32_Word    e_version;          /**< Must be equal to 1 */
  Elf32_Addr    e_entry;            /**< Address to jump to in order to start program */
  Elf32_Off     e_phoff;            /**< Program header table's file offset, in bytes */
  Elf32_Off     e_shoff;            /**< Section header table's file offset, in bytes */
  Elf32_Word    e_flags;            /**< Processor-specific flags */
  Elf32_Half    e_ehsize;           /**< Size of ELF header, in bytes */
  Elf32_Half    e_phentsize;        /**< Size of an entry in the program header table */
  Elf32_Half    e_phnum;            /**< Number of entries in the program header table */
  Elf32_Half    e_shentsize;        /**< Size of an entry in the section header table */
  Elf32_Half    e_shnum;            /**< Number of entries in the section header table */
  Elf32_Half    e_shstrndx;         /**< Sect hdr table index of sect name string table */
};


/**
 * @brief 64-bit ELF header. Fields are the same as for Elf32_Ehdr, but with different
 * types
 * @see Elf32_Ehdr
 */
struct Elf64_Ehdr {
  unsigned char e_ident[16];
  Elf64_Half    e_type;
  Elf64_Half    e_machine;
  Elf64_Word    e_version;
  Elf64_Addr    e_entry;
  Elf64_Off     e_phoff;
  Elf64_Off     e_shoff;
  Elf64_Word    e_flags;
  Elf64_Half    e_ehsize;
  Elf64_Half    e_phentsize;
  Elf64_Half    e_phnum;
  Elf64_Half    e_shentsize;
  Elf64_Half    e_shnum;
  Elf64_Half    e_shstrndx;
};


/** 32-bits Section header. */
struct Elf32_Shdr {
  Elf32_Word sh_name;      /**< Section name (index into string table) */
  Elf32_Word sh_type;      /**< Section type (SHT_*) */
  Elf32_Word sh_flags;     /**< Section flags (SHF_*) */
  Elf32_Addr sh_addr;      /**< Address where section is to be loaded */
  Elf32_Off  sh_offset;    /**< File offset of section data, in bytes */
  Elf32_Word sh_size;      /**< Size of section, in bytes */
  Elf32_Word sh_link;      /**< Section type-specific header table index link */
  Elf32_Word sh_info;      /**< Section type-specific extra information */
  Elf32_Word sh_addralign; /**< Section address alignment */
  Elf32_Word sh_entsize;   /**< Size of records contained within the section */
};

/**
 * 64-bits Section header Section header for ELF64 - same fields as Elf32_Shdr, different types.
 * @see Elf32_Shdr
 */
struct Elf64_Shdr {
  Elf64_Word  sh_name;
  Elf64_Word  sh_type;
  Elf64_Xword sh_flags;
  Elf64_Addr  sh_addr;
  Elf64_Off   sh_offset;
  Elf64_Xword sh_size;
  Elf64_Word  sh_link;
  Elf64_Word  sh_info;
  Elf64_Xword sh_addralign;
  Elf64_Xword sh_entsize;
};


/** Symbol table entries for ELF32. */
struct Elf32_Sym {
  Elf32_Word    st_name;  /**< Symbol name (index into string table) */
  Elf32_Addr    st_value; /**< Value or address associated with the symbol */
  Elf32_Word    st_size;  /**< Size of the symbol */
  unsigned char st_info;  /**< Symbol's type and binding attributes */
  unsigned char st_other; /**< Must be zero; reserved */
  Elf32_Half    st_shndx; /**< Which section (header table index) it's defined in */
};

/** Symbol table entries for ELF64. */
struct Elf64_Sym {
  Elf64_Word      st_name;  /**< Symbol name (index into string table) */
  unsigned char   st_info;  /**< Symbol's type and binding attributes */
  unsigned char   st_other; /**< Must be zero; reserved */
  Elf64_Half      st_shndx; /**< Which section (header tbl index) it's defined in */
  Elf64_Addr      st_value; /**< Value or address associated with the symbol */
  Elf64_Xword     st_size;  /**< Size of the symbol */

};

/** @brief Relocation entry, without explicit addend. */
struct Elf32_Rel {
  Elf32_Addr r_offset; /**< Location (file byte offset, or program virtual addr) */
  Elf32_Word r_info;   /**< Symbol table index and type of relocation to apply */
};

/** @brief Relocation entry with explicit addend. */
struct Elf32_Rela {
  Elf32_Addr  r_offset; /**< Location (file byte offset, or program virtual addr) */
  Elf32_Word  r_info;   /**< Symbol table index and type of relocation to apply */
  Elf32_Sword r_addend; /**< Compute value for relocatable field by adding this */
};

/** @brief Relocation entry, without explicit addend. */
struct Elf64_Rel {
  Elf64_Addr r_offset; /**< Location (file byte offset, or program virtual addr). */
  Elf64_Xword r_info;  /**< Symbol table index and type of relocation to apply. */
};

/** @brief Relocation entry with explicit addend. */
struct Elf64_Rela {
  Elf64_Addr  r_offset;  /**< Location (file byte offset, or program virtual addr). */
  Elf64_Xword  r_info;   /**< Symbol table index and type of relocation to apply. */
  Elf64_Sxword r_addend; /**< Compute value for relocatable field by adding this. */
};

/** Program header for ELF32. */
struct Elf32_Phdr {
  Elf32_Word p_type;   /**< Type of segment */
  Elf32_Off  p_offset; /**< File offset where segment is located, in bytes */
  Elf32_Addr p_vaddr;  /**< Virtual address of beginning of segment */
  Elf32_Addr p_paddr;  /**< Physical address of beginning of segment (OS-specific) */
  Elf32_Word p_filesz; /**< Num. of bytes in file image of segment (may be zero) */
  Elf32_Word p_memsz;  /**< Num. of bytes in mem image of segment (may be zero) */
  Elf32_Word p_flags;  /**< Segment flags */
  Elf32_Word p_align;  /**< Segment alignment constraint */
};

/** Program header for ELF64. */
struct Elf64_Phdr {
  Elf64_Word   p_type;   /**< Type of segment */
  Elf64_Word   p_flags;  /**< Segment flags */
  Elf64_Off    p_offset; /**< File offset where segment is located, in bytes */
  Elf64_Addr   p_vaddr;  /**< Virtual address of beginning of segment */
  Elf64_Addr   p_paddr;  /**< Physical addr of beginning of segment (OS-specific) */
  Elf64_Xword  p_filesz; /**< Num. of bytes in file image of segment (may be zero) */
  Elf64_Xword  p_memsz;  /**< Num. of bytes in mem image of segment (may be zero) */
  Elf64_Xword  p_align;  /**< Segment alignment constraint */
};


/** Dynamic table entry for ELF32. */
struct Elf32_Dyn
{
  Elf32_Sword d_tag;          /**< Type of dynamic table entry. */
  union
  {
    Elf32_Word d_val;         /**< Integer value of entry. */
    Elf32_Addr d_ptr;         /**< Pointer value of entry. */
  } d_un;
};

/** Dynamic table entry for ELF64. */
struct Elf64_Dyn
{
  Elf64_Sxword d_tag;         /**< Type of dynamic table entry. */
  union
  {
    Elf64_Xword d_val;        /**< Integer value of entry. */
    Elf64_Addr  d_ptr;        /**< Pointer value of entry. */
  } d_un;
};


struct Elf32_Verneed {
  Elf32_Half    vn_version; /**< Version of structure */
  Elf32_Half    vn_cnt;     /**< Number of associated aux entry */
  Elf32_Word    vn_file;    /**< Offset of filename for this dependency */
  Elf32_Word    vn_aux;     /**< Offset in bytes to vernaux array */
  Elf32_Word    vn_next;    /**< Offset in bytes to next verneed */
} ;

struct Elf64_Verneed {
  Elf64_Half    vn_version; /**< Version of structure */
  Elf64_Half    vn_cnt;     /**< Number of associated aux entry */
  Elf64_Word    vn_file;    /**< Offset of filename for this dependency */
  Elf64_Word    vn_aux;     /**< Offset in bytes to vernaux array */
  Elf64_Word    vn_next;    /**< Offset in bytes to next verneed */
};

struct Elf64_Vernaux {
  Elf64_Word    vna_hash;
  Elf64_Half    vna_flags;
  Elf64_Half    vna_other;
  Elf64_Word    vna_name;
  Elf64_Word    vna_next;
};

struct Elf32_Vernaux {
  Elf32_Word    vna_hash;
  Elf32_Half    vna_flags;
  Elf32_Half    vna_other;
  Elf32_Word    vna_name;
  Elf32_Word    vna_next;
};

struct Elf32_Auxv {
 uint32_t a_type;     /**< Entry type */
 union {
     uint32_t a_val;  /**< Integer value */
   } a_un;
};

struct Elf64_Auxv {
 uint64_t a_type;     /**< Entry type */
 union {
     uint64_t a_val;  /**< Integer value */
   } a_un;
};

/** Structure for .gnu.version_d (64 bits) */
struct Elf64_Verdef {
  Elf64_Half	vd_version;	/**< Version revision */
  Elf64_Half	vd_flags;		/**< Version information */
  Elf64_Half	vd_ndx;			/**< Version Index */
  Elf64_Half	vd_cnt;			/**< Number of associated aux entries */
  Elf64_Word	vd_hash;		/**< Version name hash value */
  Elf64_Word	vd_aux;			/**< Offset in bytes to verdaux array */
  Elf64_Word	vd_next;		/**< Offset in bytes to next verdef entry */
};

/** Structure for .gnu.version_d (32 bits) */
struct Elf32_Verdef {
  Elf32_Half	vd_version;	/**< Version revision */
  Elf32_Half	vd_flags;		/**< Version information */
  Elf32_Half	vd_ndx;			/**< Version Index */
  Elf32_Half	vd_cnt;			/**< Number of associated aux entries */
  Elf32_Word	vd_hash;		/**< Version name hash value */
  Elf32_Word	vd_aux;			/**< Offset in bytes to verdaux array */
  Elf32_Word	vd_next;		/**< Offset in bytes to next verdef entry */
};

struct Elf64_Verdaux
{
  Elf64_Word	vda_name;		/**< Version or dependency names */
  Elf64_Word	vda_next;		/**< Offset in bytes to next verdaux entry */
};

struct Elf32_Verdaux
{
  Elf32_Word	vda_name;		/**< Version or dependency names */
  Elf32_Word	vda_next;		/**< Offset in bytes to next verdaux entry */
};

/** Structure for note type NT_PRPSINFO */
struct Elf64_Prpsinfo
{
  char     pr_state;       /**< Numeric process state */
  char     pr_sname;       /**< Char for pr_state */
  char     pr_zomb;        /**< Process is a zombie */
  char     pr_nice;        /**< Nice value */
  uint32_t pr_pad;
  uint64_t pr_flag;        /**< Process flags */
  uint32_t pr_uid;         /**< Process user ID */
  uint32_t pr_gid;         /**< Process group ID */
  int32_t  pr_pid;         /**< Process ID */
  int32_t  pr_ppid;        /**< Process parent ID */
  int32_t  pr_pgrp;        /**< Process group */
  int32_t  pr_sid;         /**< Process session ID */
  char     pr_fname[16];   /**< Filename of executable */
  char     pr_psargs[80];  /**< Initial part of arg list */
};

struct Elf32_Prpsinfo
{
  char     pr_state;      /**< Numeric process state */
  char     pr_sname;      /**< Char for pr_state */
  char     pr_zomb;       /**< Process is a zombie */
  char     pr_nice;       /**< Nice value */
  uint32_t pr_flag;       /**< Process flags */
  uint16_t pr_uid;        /**< Process user ID */
  uint16_t pr_gid;        /**< Process group ID */
  int32_t  pr_pid;        /**< Process ID */
  int32_t  pr_ppid;       /**< Process parent ID */
  int32_t  pr_pgrp;       /**< Process group */
  int32_t  pr_sid;        /**< Process session ID */
  char     pr_fname[16];  /**< Filename of executable */
  char     pr_psargs[80]; /**< Initial part of arg list */
};

struct Elf_siginfo {
  int32_t si_signo;
  int32_t si_code;
  int32_t si_errno;
};

struct Elf32_timeval {
  uint32_t tv_sec;
  uint32_t tv_usec;
};

struct Elf64_timeval {
  uint64_t tv_sec;
  uint64_t tv_usec;
};

/** Structure for note type NT_PRSTATUS */
struct Elf32_Prstatus {
  Elf_siginfo   pr_info;
  uint16_t      pr_cursig;
  uint16_t      reserved;

  uint32_t      pr_sigpend;
  uint32_t      pr_sighold;

  int32_t       pr_pid;
  int32_t       pr_ppid;
  int32_t       pr_pgrp;
  int32_t       pr_sid;

  Elf32_timeval pr_utime;
  Elf32_timeval pr_stime;
  Elf32_timeval pr_cutime;
  Elf32_timeval pr_cstime;
};

struct Elf64_Prstatus {
  Elf_siginfo   pr_info;
  uint16_t      pr_cursig;
  uint16_t      reserved;

  uint64_t      pr_sigpend;
  uint64_t      pr_sighold;

  int32_t       pr_pid;
  int32_t       pr_ppid;
  int32_t       pr_pgrp;
  int32_t       pr_sid;

  Elf64_timeval pr_utime;
  Elf64_timeval pr_stime;
  Elf64_timeval pr_cutime;
  Elf64_timeval pr_cstime;
};

/** Structure for note type NT_FILE */
struct Elf64_FileEntry
{
  uint64_t start;
  uint64_t end;
  uint64_t file_ofs;
};

struct Elf32_FileEntry
{
  uint32_t start;
  uint32_t end;
  uint32_t file_ofs;
};

#pragma pack(pop)



static const ELF_SECTION_FLAGS section_flags_array[] = {
  ELF_SECTION_FLAGS::SHF_NONE, ELF_SECTION_FLAGS::SHF_WRITE, ELF_SECTION_FLAGS::SHF_ALLOC, ELF_SECTION_FLAGS::SHF_EXECINSTR,
   ELF_SECTION_FLAGS::SHF_MERGE, ELF_SECTION_FLAGS::SHF_STRINGS, ELF_SECTION_FLAGS::SHF_INFO_LINK,
   ELF_SECTION_FLAGS::SHF_LINK_ORDER, ELF_SECTION_FLAGS::SHF_OS_NONCONFORMING, ELF_SECTION_FLAGS::SHF_GROUP,
   ELF_SECTION_FLAGS::SHF_TLS, ELF_SECTION_FLAGS::SHF_EXCLUDE, ELF_SECTION_FLAGS::XCORE_SHF_CP_SECTION,
   ELF_SECTION_FLAGS::XCORE_SHF_DP_SECTION, ELF_SECTION_FLAGS::SHF_MASKOS, ELF_SECTION_FLAGS::SHF_MASKPROC,
   ELF_SECTION_FLAGS::SHF_HEX_GPREL, ELF_SECTION_FLAGS::SHF_MIPS_NODUPES, ELF_SECTION_FLAGS::SHF_MIPS_NAMES,
   ELF_SECTION_FLAGS::SHF_MIPS_LOCAL, ELF_SECTION_FLAGS::SHF_MIPS_NOSTRIP, ELF_SECTION_FLAGS::SHF_MIPS_GPREL,
   ELF_SECTION_FLAGS::SHF_MIPS_MERGE, ELF_SECTION_FLAGS::SHF_MIPS_ADDR, ELF_SECTION_FLAGS::SHF_MIPS_STRING
};


static const ARM_EFLAGS arm_eflags_array[] = {
  ARM_EFLAGS::EF_ARM_SOFT_FLOAT,
  ARM_EFLAGS::EF_ARM_VFP_FLOAT,
  ARM_EFLAGS::EF_ARM_EABI_UNKNOWN,
  ARM_EFLAGS::EF_ARM_EABI_VER1,
  ARM_EFLAGS::EF_ARM_EABI_VER2,
  ARM_EFLAGS::EF_ARM_EABI_VER3,
  ARM_EFLAGS::EF_ARM_EABI_VER4,
  ARM_EFLAGS::EF_ARM_EABI_VER5,
};

static const PPC64_EFLAGS ppc64_eflags_array[] = {
  PPC64_EFLAGS::EF_PPC64_ABI,
};

static const MIPS_EFLAGS mips_eflags_array[] = {
  MIPS_EFLAGS::EF_MIPS_NOREORDER,
  MIPS_EFLAGS::EF_MIPS_PIC,
  MIPS_EFLAGS::EF_MIPS_CPIC,
  MIPS_EFLAGS::EF_MIPS_ABI2,
  MIPS_EFLAGS::EF_MIPS_32BITMODE,
  MIPS_EFLAGS::EF_MIPS_FP64,
  MIPS_EFLAGS::EF_MIPS_NAN2008,
  MIPS_EFLAGS::EF_MIPS_ABI_O32,
  MIPS_EFLAGS::EF_MIPS_ABI_O64,
  MIPS_EFLAGS::EF_MIPS_ABI_EABI32,
  MIPS_EFLAGS::EF_MIPS_ABI_EABI64,
  MIPS_EFLAGS::EF_MIPS_MACH_3900,
  MIPS_EFLAGS::EF_MIPS_MACH_4010,
  MIPS_EFLAGS::EF_MIPS_MACH_4100,
  MIPS_EFLAGS::EF_MIPS_MACH_4650,
  MIPS_EFLAGS::EF_MIPS_MACH_4120,
  MIPS_EFLAGS::EF_MIPS_MACH_4111,
  MIPS_EFLAGS::EF_MIPS_MACH_SB1,
  MIPS_EFLAGS::EF_MIPS_MACH_OCTEON,
  MIPS_EFLAGS::EF_MIPS_MACH_XLR,
  MIPS_EFLAGS::EF_MIPS_MACH_OCTEON2,
  MIPS_EFLAGS::EF_MIPS_MACH_OCTEON3,
  MIPS_EFLAGS::EF_MIPS_MACH_5400,
  MIPS_EFLAGS::EF_MIPS_MACH_5900,
  MIPS_EFLAGS::EF_MIPS_MACH_5500,
  MIPS_EFLAGS::EF_MIPS_MACH_9000,
  MIPS_EFLAGS::EF_MIPS_MACH_LS2E,
  MIPS_EFLAGS::EF_MIPS_MACH_LS2F,
  MIPS_EFLAGS::EF_MIPS_MACH_LS3A,
  MIPS_EFLAGS::EF_MIPS_MICROMIPS,
  MIPS_EFLAGS::EF_MIPS_ARCH_ASE_M16,
  MIPS_EFLAGS::EF_MIPS_ARCH_ASE_MDMX,
  MIPS_EFLAGS::EF_MIPS_ARCH_1,
  MIPS_EFLAGS::EF_MIPS_ARCH_2,
  MIPS_EFLAGS::EF_MIPS_ARCH_3,
  MIPS_EFLAGS::EF_MIPS_ARCH_4,
  MIPS_EFLAGS::EF_MIPS_ARCH_5,
  MIPS_EFLAGS::EF_MIPS_ARCH_32,
  MIPS_EFLAGS::EF_MIPS_ARCH_64,
  MIPS_EFLAGS::EF_MIPS_ARCH_32R2,
  MIPS_EFLAGS::EF_MIPS_ARCH_64R2,
  MIPS_EFLAGS::EF_MIPS_ARCH_32R6,
  MIPS_EFLAGS::EF_MIPS_ARCH_64R6,
};

static const HEXAGON_EFLAGS hexagon_eflags_array[] = {
  HEXAGON_EFLAGS::EF_HEXAGON_MACH_V2,
  HEXAGON_EFLAGS::EF_HEXAGON_MACH_V3,
  HEXAGON_EFLAGS::EF_HEXAGON_MACH_V4,
  HEXAGON_EFLAGS::EF_HEXAGON_MACH_V5,
  HEXAGON_EFLAGS::EF_HEXAGON_ISA_MACH,
  HEXAGON_EFLAGS::EF_HEXAGON_ISA_V2,
  HEXAGON_EFLAGS::EF_HEXAGON_ISA_V3,
  HEXAGON_EFLAGS::EF_HEXAGON_ISA_V4,
  HEXAGON_EFLAGS::EF_HEXAGON_ISA_V5,
};

static const DYNAMIC_FLAGS dynamic_flags_array[] = {
  DYNAMIC_FLAGS::DF_ORIGIN,
  DYNAMIC_FLAGS::DF_SYMBOLIC,
  DYNAMIC_FLAGS::DF_TEXTREL,
  DYNAMIC_FLAGS::DF_BIND_NOW,
  DYNAMIC_FLAGS::DF_STATIC_TLS,
};


static const DYNAMIC_FLAGS_1 dynamic_flags_1_array[] = {
  DYNAMIC_FLAGS_1::DF_1_NOW,
  DYNAMIC_FLAGS_1::DF_1_GLOBAL,
  DYNAMIC_FLAGS_1::DF_1_GROUP,
  DYNAMIC_FLAGS_1::DF_1_NODELETE,
  DYNAMIC_FLAGS_1::DF_1_LOADFLTR,
  DYNAMIC_FLAGS_1::DF_1_INITFIRST,
  DYNAMIC_FLAGS_1::DF_1_NOOPEN,
  DYNAMIC_FLAGS_1::DF_1_ORIGIN,
  DYNAMIC_FLAGS_1::DF_1_DIRECT,
  DYNAMIC_FLAGS_1::DF_1_TRANS,
  DYNAMIC_FLAGS_1::DF_1_INTERPOSE,
  DYNAMIC_FLAGS_1::DF_1_NODEFLIB,
  DYNAMIC_FLAGS_1::DF_1_NODUMP,
  DYNAMIC_FLAGS_1::DF_1_CONFALT,
  DYNAMIC_FLAGS_1::DF_1_ENDFILTEE,
  DYNAMIC_FLAGS_1::DF_1_DISPRELDNE,
  DYNAMIC_FLAGS_1::DF_1_DISPRELPND,
  DYNAMIC_FLAGS_1::DF_1_NODIRECT,
  DYNAMIC_FLAGS_1::DF_1_IGNMULDEF,
  DYNAMIC_FLAGS_1::DF_1_NOKSYMS,
  DYNAMIC_FLAGS_1::DF_1_NOHDR,
  DYNAMIC_FLAGS_1::DF_1_EDITED,
  DYNAMIC_FLAGS_1::DF_1_NORELOC,
  DYNAMIC_FLAGS_1::DF_1_SYMINTPOSE,
  DYNAMIC_FLAGS_1::DF_1_GLOBAUDIT,
  DYNAMIC_FLAGS_1::DF_1_SINGLETON,
  DYNAMIC_FLAGS_1::DF_1_PIE,
};



class ELF32 {
  public:
  typedef Elf32_Addr    Elf_Addr;
  typedef Elf32_Off     Elf_Off;
  typedef Elf32_Half    Elf_Half;
  typedef Elf32_Word    Elf_Word;
  typedef Elf32_Sword   Elf_Sword;
  // Equivalent
  typedef Elf32_Addr    Elf_Xword;
  typedef Elf32_Sword   Elf_Sxword;

  typedef uint32_t      uint;

  typedef Elf32_Phdr    Elf_Phdr;
  typedef Elf32_Ehdr    Elf_Ehdr;
  typedef Elf32_Shdr    Elf_Shdr;
  typedef Elf32_Sym     Elf_Sym;
  typedef Elf32_Rel     Elf_Rel;
  typedef Elf32_Rela    Elf_Rela;
  typedef Elf32_Dyn     Elf_Dyn;
  typedef Elf32_Verneed Elf_Verneed;
  typedef Elf32_Vernaux Elf_Vernaux;
  typedef Elf32_Auxv    Elf_Auxv;
  typedef Elf32_Verdef  Elf_Verdef;
  typedef Elf32_Verdaux Elf_Verdaux;

  typedef Elf32_Prpsinfo  Elf_Prpsinfo;
  typedef Elf32_FileEntry Elf_FileEntry;
  typedef Elf32_Prstatus  Elf_Prstatus;

  typedef Elf32_timeval   Elf_timeval;
};


class ELF64 {
  public:
  typedef Elf64_Addr    Elf_Addr;
  typedef Elf64_Off     Elf_Off;
  typedef Elf64_Half    Elf_Half;
  typedef Elf64_Word    Elf_Word;
  typedef Elf64_Sword   Elf_Sword;

  typedef Elf64_Xword   Elf_Xword;
  typedef Elf64_Sxword  Elf_Sxword;

  typedef uint64_t      uint;

  typedef Elf64_Phdr    Elf_Phdr;
  typedef Elf64_Ehdr    Elf_Ehdr;
  typedef Elf64_Shdr    Elf_Shdr;
  typedef Elf64_Sym     Elf_Sym;
  typedef Elf64_Rel     Elf_Rel;
  typedef Elf64_Rela    Elf_Rela;
  typedef Elf64_Dyn     Elf_Dyn;
  typedef Elf64_Verneed Elf_Verneed;
  typedef Elf64_Vernaux Elf_Vernaux;
  typedef Elf64_Auxv    Elf_Auxv;
  typedef Elf64_Verdef  Elf_Verdef;
  typedef Elf64_Verdaux Elf_Verdaux;

  typedef Elf64_Prpsinfo  Elf_Prpsinfo;
  typedef Elf64_FileEntry Elf_FileEntry;
  typedef Elf64_Prstatus  Elf_Prstatus;

  typedef Elf64_timeval   Elf_timeval;
 };

} /* end namespace ELF */
} /* end namespace LIEF */
#endif
