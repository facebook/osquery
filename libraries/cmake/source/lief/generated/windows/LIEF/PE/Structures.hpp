#ifndef LIEF_PE_STRUCTURES_H_
#define LIEF_PE_STRUCTURES_H_
#include <type_traits>
#include <map>

#include "LIEF/types.hpp"

#include "LIEF/PE/enums.hpp"

namespace LIEF {

//! Namespace related to the LIEF's PE module
//!
//! Some parts from llvm/Support/COFF.h
namespace PE {

//! Sizes in bytes of various things in the COFF format.
namespace STRUCT_SIZES {
  enum {
    Header16Size                  = 20,
    Header32Size                  = 56,
    NameSize                      = 8,
    Symbol16Size                  = 18,
    Symbol32Size                  = 20,
    SectionSize                   = 40,
    RelocationSize                = 10,
    BaseRelocationBlockSize       = 8,
    ImportDirectoryTableEntrySize = 20,
    ResourceDirectoryTableSize    = 16,
    ResourceDirectoryEntriesSize  = 8,
    ResourceDataEntrySize         = 16
  };
}



//! The maximum number of sections that a COFF object can have (inclusive).
static const int32_t MaxNumberOfSections16 = 65279;

//! The PE signature bytes that follows the DOS stub header.
static const char PE_Magic[] = { 'P', 'E', '\0', '\0' };

static const char Rich_Magic[] = {'R', 'i', 'c', 'h'};
static const char DanS_Magic[] = {'D', 'a', 'n', 'S'};

static const uint32_t DanS_Magic_number = 0x536E6144;

static const char BigObjMagic[] = {
  '\xc7', '\xa1', '\xba', '\xd1', '\xee', '\xba', '\xa9', '\x4b',
  '\xaf', '\x20', '\xfa', '\xf6', '\x6a', '\xa4', '\xdc', '\xb8',
};

static const uint8_t DEFAULT_NUMBER_DATA_DIRECTORIES = 15;

#pragma pack(push,1)
struct pe_header {
  char     signature[sizeof(PE_Magic)];
  uint16_t Machine;
  uint16_t NumberOfSections;
  uint32_t TimeDateStamp;
  uint32_t PointerToSymbolTable;
  uint32_t NumberOfSymbols;
  uint16_t SizeOfOptionalHeader;
  uint16_t Characteristics;
};


struct pe_relocation {
  uint32_t VirtualAddress;
  uint32_t SymbolTableIndex;
  uint16_t Type;
};

struct pe_base_relocation_block {
  uint32_t PageRVA;
  uint32_t BlockSize;
};


struct pe_symbol {
  union {
    char ShortName[8];
    struct
    {
      uint32_t Zeroes;
      uint32_t Offset;
    } Name;
  } Name;
  uint32_t Value;
  int16_t  SectionNumber;
  uint16_t Type;
  uint8_t  StorageClass;
  uint8_t  NumberOfAuxSymbols;
};


struct pe_section {
  char     Name[8];
  uint32_t VirtualSize;
  uint32_t VirtualAddress;
  uint32_t SizeOfRawData;
  uint32_t PointerToRawData;
  uint32_t PointerToRelocations;
  uint32_t PointerToLineNumbers;
  uint16_t NumberOfRelocations;
  uint16_t NumberOfLineNumbers;
  uint32_t Characteristics;
};

struct AuxiliaryFunctionDefinition {
  uint32_t TagIndex;
  uint32_t TotalSize;
  uint32_t PointerToLinenumber;
  uint32_t PointerToNextFunction;
  char     unused[2];
};

struct AuxiliarybfAndefSymbol {
  uint8_t  unused1[4];
  uint16_t Linenumber;
  uint8_t  unused2[6];
  uint32_t PointerToNextFunction;
  uint8_t  unused3[2];
};

struct AuxiliaryWeakExternal {
  uint32_t TagIndex;
  uint32_t Characteristics;
  uint8_t  unused[10];
};


struct AuxiliarySectionDefinition {
  uint32_t Length;
  uint16_t NumberOfRelocations;
  uint16_t NumberOfLinenumbers;
  uint32_t CheckSum;
  uint32_t Number;
  uint8_t  Selection;
  char     unused;
};

struct AuxiliaryCLRToken {
  uint8_t  AuxType;
  uint8_t  unused1;
  uint32_t SymbolTableIndex;
  char     unused2[12];
};

union Auxiliary {
  AuxiliaryFunctionDefinition FunctionDefinition;
  AuxiliarybfAndefSymbol      bfAndefSymbol;
  AuxiliaryWeakExternal       WeakExternal;
  AuxiliarySectionDefinition  SectionDefinition;
};


/// The Import Directory Table.
///
/// There is a single array of these and one entry per imported DLL.
struct pe_import {
  uint32_t ImportLookupTableRVA;
  uint32_t TimeDateStamp;
  uint32_t ForwarderChain;
  uint32_t NameRVA;
  uint32_t ImportAddressTableRVA;
};


struct ImportLookupTableEntry32 {
  uint32_t data;
};

struct ImportLookupTableEntry64 {
  uint64_t data;
};


struct pe32_tls {
  uint32_t RawDataStartVA;
  uint32_t RawDataEndVA;
  uint32_t AddressOfIndex;
  uint32_t AddressOfCallback;
  uint32_t SizeOfZeroFill;
  uint32_t Characteristics;
};


struct pe64_tls {
  uint64_t RawDataStartVA;
  uint64_t RawDataEndVA;
  uint64_t AddressOfIndex;
  uint64_t AddressOfCallback;
  uint32_t SizeOfZeroFill;
  uint32_t Characteristics;
};


/// The DOS compatible header at the front of all PEs.
struct pe_dos_header {
  uint16_t Magic;
  uint16_t UsedBytesInTheLastPage;
  uint16_t FileSizeInPages;
  uint16_t NumberOfRelocationItems;
  uint16_t HeaderSizeInParagraphs;
  uint16_t MinimumExtraParagraphs;
  uint16_t MaximumExtraParagraphs;
  uint16_t InitialRelativeSS;
  uint16_t InitialSP;
  uint16_t Checksum;
  uint16_t InitialIP;
  uint16_t InitialRelativeCS;
  uint16_t AddressOfRelocationTable;
  uint16_t OverlayNumber;
  uint16_t Reserved[4];
  uint16_t OEMid;
  uint16_t OEMinfo;
  uint16_t Reserved2[10];
  uint32_t AddressOfNewExeHeader;
};

struct pe64_optional_header {
  uint16_t Magic;
  uint8_t  MajorLinkerVersion;
  uint8_t  MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint; // RVA
  uint32_t BaseOfCode; // RVA
  //uint32_t BaseOfData; // RVA
  uint64_t ImageBase;
  uint32_t SectionAlignment;
  uint32_t FileAlignment;
  uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion;
  uint16_t MajorImageVersion;
  uint16_t MinorImageVersion;
  uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion;
  uint32_t Win32VersionValue;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;
  uint16_t Subsystem;
  uint16_t DLLCharacteristics;
  uint64_t SizeOfStackReserve;
  uint64_t SizeOfStackCommit;
  uint64_t SizeOfHeapReserve;
  uint64_t SizeOfHeapCommit;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSize;
};


struct pe32_optional_header {
  uint16_t Magic;
  uint8_t  MajorLinkerVersion;
  uint8_t  MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint; // RVA
  uint32_t BaseOfCode; // RVA
  uint32_t BaseOfData; // RVA
  uint32_t ImageBase;
  uint32_t SectionAlignment;
  uint32_t FileAlignment;
  uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion;
  uint16_t MajorImageVersion;
  uint16_t MinorImageVersion;
  uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion;
  uint32_t Win32VersionValue;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;
  uint16_t Subsystem;
  uint16_t DLLCharacteristics;
  uint32_t SizeOfStackReserve;
  uint32_t SizeOfStackCommit;
  uint32_t SizeOfHeapReserve;
  uint32_t SizeOfHeapCommit;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSize;
};


struct pe_data_directory {
  uint32_t RelativeVirtualAddress;
  uint32_t Size;
};


struct pe_debug {
  uint32_t Characteristics;
  uint32_t TimeDateStamp;
  uint16_t MajorVersion;
  uint16_t MinorVersion;
  uint32_t Type;
  uint32_t SizeOfData;
  uint32_t AddressOfRawData;
  uint32_t PointerToRawData;
};


struct pe_pdb_70 {
  uint32_t cv_signature;
  uint8_t  signature[16];
  uint32_t age;
  char*    filename;
};

struct pe_pdb_20 {
  uint32_t cv_signature;
  uint32_t offset;
  uint32_t signature;
  uint32_t age;
  char*    filename;
};

struct pe_pogo {
  uint32_t start_rva;
  uint32_t size;
  char     name[1];
};


struct pe_resource_directory_table {
  uint32_t Characteristics;
  uint32_t TimeDateStamp;
  uint16_t MajorVersion;
  uint16_t MinorVersion;
  uint16_t NumberOfNameEntries;
  uint16_t NumberOfIDEntries;
};

struct pe_resource_directory_entries {
  union {
    uint32_t NameRVA;
    uint32_t IntegerID;
  } NameID;
  uint32_t RVA;
};

struct pe_resource_data_entry {
  uint32_t DataRVA;
  uint32_t Size;
  uint32_t Codepage;
  uint32_t Reserved;
};

struct pe_resource_string {
  int16_t Length;
  uint16_t Name[1];
};

struct pe_resource_acceltableentry {
  int16_t fFlags;
  int16_t wAnsi;
  int16_t wId;
  int16_t padding;
};

//
// Export structures
//
struct pe_export_directory_table {
  uint32_t ExportFlags;           ///< Reserverd must be 0
  uint32_t Timestamp;             ///< The time and date that the export data was created
  uint16_t MajorVersion;          ///< The Major version number
  uint16_t MinorVersion;          ///< The Minor version number
  uint32_t NameRVA;               ///< The address of the ASCII DLL's name (RVA)
  uint32_t OrdinalBase;           ///< The starting ordinal number for exports. (Usually 1)
  uint32_t AddressTableEntries;   ///< Number of entries in the export address table
  uint32_t NumberOfNamePointers;  ///< Number of entries in the name pointer table
  uint32_t ExportAddressTableRVA; ///< Address of the export address table (RVA)
  uint32_t NamePointerRVA;        ///< Address of the name pointer table (RVA)
  uint32_t OrdinalTableRVA;       ///< Address of the ordinal table (RVA)
};


struct pe_resource_fixed_file_info {
  uint32_t signature;          // e.g.  0xfeef04bd
  uint32_t struct_version;      // e.g.  0x00000042 = "0.42"
  uint32_t file_version_MS;    // e.g.  0x00030075 = "3.75"
  uint32_t file_version_LS;    // e.g.  0x00000031 = "0.31"
  uint32_t product_version_MS; // e.g.  0x00030010 = "3.10"
  uint32_t product_version_LS; // e.g.  0x00000031 = "0.31"
  uint32_t file_flags_mask;    // = 0x3F for version "0.42"
  uint32_t file_flags;         // e.g.  VFF_DEBUG | VFF_PRERELEASE
  uint32_t file_OS;            // e.g.  VOS_DOS_WINDOWS16
  uint32_t file_type;          // e.g.  VFT_DRIVER
  uint32_t file_subtype;       // e.g.  VFT2_DRV_KEYBOARD
  uint32_t file_date_MS;       // e.g.  0
  uint32_t file_date_LS;       // e.g.  0
};


struct pe_resource_version_info {
  uint16_t length;
  uint16_t sizeof_value;
  uint16_t type;
  char16_t key[16];
  // uint16_t padding;
  //
  // uint16_t padding;
  // uint16_t children
};

//! Resource icons directory structure
//! Based on https://docs.microsoft.com/en-us/windows/win32/menurc/resources-reference
//!
//! This is the begining of the RESOURCE_TYPES::GROUP_ICON content
struct pe_resource_icon_dir {
  uint16_t reserved; ///< Reserved
  uint16_t type;     ///< Resource type (1 for icons)
  uint16_t count;    ///< Number of icons
};


//! Structure that follows pe_resource_icon_dir in a resource entry
struct pe_resource_icon_group {
  uint8_t width;        ///< Width, in pixels, of the image
  uint8_t height;       ///< Height, in pixels, of the image
  uint8_t color_count;  ///< Number of colors in image (0 if >=8bpp)
  uint8_t reserved;     ///< Reserved (must be 0)
  uint16_t planes;      ///< Color Planes
  uint16_t bit_count;   ///< Bits per pixel
  uint32_t size;        ///< Size of the image in bytes
  uint16_t ID;          ///< The associated ID
};

//! Structure that follows pe_resource_icon_dir in a icon **file**
struct pe_icon_header {
  uint8_t width;        ///< Width, in pixels, of the image
  uint8_t height;       ///< Height, in pixels, of the image
  uint8_t color_count;  ///< Number of colors in image (0 if >=8bpp)
  uint8_t reserved;     ///< Reserved (must be 0)
  uint16_t planes;      ///< Color Planes
  uint16_t bit_count;   ///< Bits per pixel
  uint32_t size;        ///< Size of the image in bytes
  uint32_t offset;      ///< Offset to the pixels
};

//! Extended dialog box template
struct pe_dialog_template_ext {
  uint16_t version;
  uint16_t signature;
  uint32_t help_id;
  uint32_t ext_style;
  uint32_t style;
  uint16_t nbof_items;
  int16_t x;
  int16_t y;
  int16_t cx;
  int16_t cy;
  // sz_Or_Ord menu;
  // sz_Or_Ord windowClass;
  // char16_t  title[titleLen];
  // uint16_t  pointsize;
  // uint16_t  weight;
  // uint8_t   italic;
  // uint8_t   charset;
  // char16_t  typeface[stringLen];
};

//! Dialog box template
struct pe_dialog_template {
  uint32_t style;
  uint32_t ext_style;
  uint16_t nbof_items;
  int16_t x;
  int16_t y;
  int16_t cx;
  int16_t cy;
};


//! Extended dialog box template item
struct pe_dialog_item_template_ext {
  uint32_t help_id;
  uint32_t ext_style;
  uint32_t style;
  int16_t x;
  int16_t y;
  int16_t cx;
  int16_t cy;
  uint32_t id;
  // sz_Or_Ord windowClass;
  // sz_Or_Ord title;
  // uint16_t extra_count;
};


//! Dialog box template item
struct pe_dialog_item_template {
  uint32_t style;
  uint32_t ext_style;
  int16_t x;
  int16_t y;
  int16_t cx;
  int16_t cy;
  uint16_t id;
};

struct pe_code_integrity {
  uint16_t Flags;
  uint16_t Catalog;
  uint32_t CatalogOffset;
  uint32_t Reserved;
};

struct pe_exception_entry_x64 {
  uint32_t address_start_rva;
  uint32_t address_end_rva;
  uint32_t unwind_info_rva;
};


struct pe_exception_entry_mips {
  uint32_t address_start_va;
  uint32_t address_end_va;
  uint32_t exception_handler;
  uint32_t handler_data;
  uint32_t prolog_end_address;
};

struct pe_exception_entry_arm {
  uint32_t address_start_va;
  uint32_t data;
};

#pragma pack(pop)


static const HEADER_CHARACTERISTICS header_characteristics_array[] = {
  HEADER_CHARACTERISTICS::IMAGE_FILE_INVALID,
  HEADER_CHARACTERISTICS::IMAGE_FILE_RELOCS_STRIPPED,
  HEADER_CHARACTERISTICS::IMAGE_FILE_EXECUTABLE_IMAGE,
  HEADER_CHARACTERISTICS::IMAGE_FILE_LINE_NUMS_STRIPPED,
  HEADER_CHARACTERISTICS::IMAGE_FILE_LOCAL_SYMS_STRIPPED,
  HEADER_CHARACTERISTICS::IMAGE_FILE_AGGRESSIVE_WS_TRIM,
  HEADER_CHARACTERISTICS::IMAGE_FILE_LARGE_ADDRESS_AWARE,
  HEADER_CHARACTERISTICS::IMAGE_FILE_BYTES_REVERSED_LO,
  HEADER_CHARACTERISTICS::IMAGE_FILE_32BIT_MACHINE,
  HEADER_CHARACTERISTICS::IMAGE_FILE_DEBUG_STRIPPED,
  HEADER_CHARACTERISTICS::IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,
  HEADER_CHARACTERISTICS::IMAGE_FILE_NET_RUN_FROM_SWAP,
  HEADER_CHARACTERISTICS::IMAGE_FILE_SYSTEM,
  HEADER_CHARACTERISTICS::IMAGE_FILE_DLL,
  HEADER_CHARACTERISTICS::IMAGE_FILE_UP_SYSTEM_ONLY,
  HEADER_CHARACTERISTICS::IMAGE_FILE_BYTES_REVERSED_HI
};


static const SECTION_CHARACTERISTICS section_characteristics_array[] = {
  SECTION_CHARACTERISTICS::IMAGE_SCN_TYPE_NO_PAD,
  SECTION_CHARACTERISTICS::IMAGE_SCN_CNT_CODE,
  SECTION_CHARACTERISTICS::IMAGE_SCN_CNT_INITIALIZED_DATA,
  SECTION_CHARACTERISTICS::IMAGE_SCN_CNT_UNINITIALIZED_DATA,
  SECTION_CHARACTERISTICS::IMAGE_SCN_LNK_OTHER,
  SECTION_CHARACTERISTICS::IMAGE_SCN_LNK_INFO,
  SECTION_CHARACTERISTICS::IMAGE_SCN_LNK_REMOVE,
  SECTION_CHARACTERISTICS::IMAGE_SCN_LNK_COMDAT,
  SECTION_CHARACTERISTICS::IMAGE_SCN_GPREL,
  SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_PURGEABLE,
  SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_16BIT,
  SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_LOCKED,
  SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_PRELOAD,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_1BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_2BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_4BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_8BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_16BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_32BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_64BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_128BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_256BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_512BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_1024BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_2048BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_4096BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_8192BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_LNK_NRELOC_OVFL,
  SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_DISCARDABLE,
  SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_NOT_CACHED,
  SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_NOT_PAGED,
  SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_SHARED,
  SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_EXECUTE,
  SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_READ,
  SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_WRITE,
};



static const DLL_CHARACTERISTICS dll_characteristics_array[] = {
  DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA,
  DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE,
  DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY,
  DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_NX_COMPAT,
  DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_NO_ISOLATION,
  DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_NO_SEH,
  DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_NO_BIND,
  DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_APPCONTAINER,
  DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_WDM_DRIVER,
  DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_GUARD_CF,
  DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_TERMINAL_SERVER_AWARE,
};


static const EXTENDED_WINDOW_STYLES extended_window_styles_array[] = {
  EXTENDED_WINDOW_STYLES::WS_EX_DLGMODALFRAME,
  EXTENDED_WINDOW_STYLES::WS_EX_NOPARENTNOTIFY,
  EXTENDED_WINDOW_STYLES::WS_EX_TOPMOST,
  EXTENDED_WINDOW_STYLES::WS_EX_ACCEPTFILES,
  EXTENDED_WINDOW_STYLES::WS_EX_TRANSPARENT,
  EXTENDED_WINDOW_STYLES::WS_EX_MDICHILD,
  EXTENDED_WINDOW_STYLES::WS_EX_TOOLWINDOW,
  EXTENDED_WINDOW_STYLES::WS_EX_WINDOWEDGE,
  EXTENDED_WINDOW_STYLES::WS_EX_CLIENTEDGE,
  EXTENDED_WINDOW_STYLES::WS_EX_CONTEXTHELP,
  EXTENDED_WINDOW_STYLES::WS_EX_RIGHT,
  EXTENDED_WINDOW_STYLES::WS_EX_LEFT,
  EXTENDED_WINDOW_STYLES::WS_EX_RTLREADING,
  EXTENDED_WINDOW_STYLES::WS_EX_LTRREADING,
  EXTENDED_WINDOW_STYLES::WS_EX_LEFTSCROLLBAR,
  EXTENDED_WINDOW_STYLES::WS_EX_RIGHTSCROLLBAR,
  EXTENDED_WINDOW_STYLES::WS_EX_CONTROLPARENT,
  EXTENDED_WINDOW_STYLES::WS_EX_STATICEDGE,
  EXTENDED_WINDOW_STYLES::WS_EX_APPWINDOW,
};


static const WINDOW_STYLES window_styles_array[] = {
  WINDOW_STYLES::WS_OVERLAPPED,
  WINDOW_STYLES::WS_POPUP,
  WINDOW_STYLES::WS_CHILD,
  WINDOW_STYLES::WS_MINIMIZE,
  WINDOW_STYLES::WS_VISIBLE,
  WINDOW_STYLES::WS_DISABLED,
  WINDOW_STYLES::WS_CLIPSIBLINGS,
  WINDOW_STYLES::WS_CLIPCHILDREN,
  WINDOW_STYLES::WS_MAXIMIZE,
  WINDOW_STYLES::WS_CAPTION,
  WINDOW_STYLES::WS_BORDER,
  WINDOW_STYLES::WS_DLGFRAME,
  WINDOW_STYLES::WS_VSCROLL,
  WINDOW_STYLES::WS_HSCROLL,
  WINDOW_STYLES::WS_SYSMENU,
  WINDOW_STYLES::WS_THICKFRAME,
  WINDOW_STYLES::WS_GROUP,
  WINDOW_STYLES::WS_TABSTOP,
  WINDOW_STYLES::WS_MINIMIZEBOX,
  WINDOW_STYLES::WS_MAXIMIZEBOX,
};


static const DIALOG_BOX_STYLES dialog_box_styles_array[] = {
  DIALOG_BOX_STYLES::DS_ABSALIGN,
  DIALOG_BOX_STYLES::DS_SYSMODAL,
  DIALOG_BOX_STYLES::DS_LOCALEDIT,
  DIALOG_BOX_STYLES::DS_SETFONT,
  DIALOG_BOX_STYLES::DS_MODALFRAME,
  DIALOG_BOX_STYLES::DS_NOIDLEMSG,
  DIALOG_BOX_STYLES::DS_SETFOREGROUND,
  DIALOG_BOX_STYLES::DS_3DLOOK,
  DIALOG_BOX_STYLES::DS_FIXEDSYS,
  DIALOG_BOX_STYLES::DS_NOFAILCREATE,
  DIALOG_BOX_STYLES::DS_CONTROL,
  DIALOG_BOX_STYLES::DS_CENTER,
  DIALOG_BOX_STYLES::DS_CENTERMOUSE,
  DIALOG_BOX_STYLES::DS_CONTEXTHELP,
  DIALOG_BOX_STYLES::DS_SHELLFONT,
};

static const ACCELERATOR_FLAGS accelerator_array[] = {
  ACCELERATOR_FLAGS::FVIRTKEY,
  ACCELERATOR_FLAGS::FNOINVERT,
  ACCELERATOR_FLAGS::FSHIFT,
  ACCELERATOR_FLAGS::FCONTROL,
  ACCELERATOR_FLAGS::FALT,
  ACCELERATOR_FLAGS::END,
};

// From Virtualbox - include/iprt/formats/pecoff.h
template <typename T>
struct load_configuration {
  uint32_t Characteristics;
  uint32_t TimeDateStamp;
  uint16_t MajorVersion;
  uint16_t MinorVersion;
  uint32_t GlobalFlagsClear;
  uint32_t GlobalFlagsSet;
  uint32_t CriticalSectionDefaultTimeout;
  T        DeCommitFreeBlockThreshold;
  T        DeCommitTotalFreeThreshold;
  T        LockPrefixTable;
  T        MaximumAllocationSize;
  T        VirtualMemoryThreshold;
  T        ProcessAffinityMask;
  uint32_t ProcessHeapFlags;
  uint16_t CSDVersion;
  uint16_t Reserved1;
  T        EditList;
  T        SecurityCookie;
};

template <typename T>
struct load_configuration_v0 : load_configuration<T> {
  T SEHandlerTable;
  T SEHandlerCount;
};


#pragma pack(4)
// Windows 10 - 9879

template <typename T>
struct load_configuration_v1 : load_configuration_v0<T> {
  T        GuardCFCheckFunctionPointer;
  T        GuardCFDispatchFunctionPointer;
  T        GuardCFFunctionTable;
  T        GuardCFFunctionCount;
  uint32_t GuardFlags;
};
#pragma pack()


// Windows 10 - 9879
template <typename T>
struct load_configuration_v2 : load_configuration_v1<T> {
  pe_code_integrity CodeIntegrity;
};


template <typename T>
struct load_configuration_v3 : load_configuration_v2<T> {
  T GuardAddressTakenIatEntryTable;
  T GuardAddressTakenIatEntryCount;
  T GuardLongJumpTargetTable;
  T GuardLongJumpTargetCount;
};


template <typename T>
struct load_configuration_v4 : load_configuration_v3<T> {
  T DynamicValueRelocTable;
  T HybridMetadataPointer;
};


template <typename T>
struct load_configuration_v5 : load_configuration_v4<T> {
  T        GuardRFFailureRoutine;
  T        GuardRFFailureRoutineFunctionPointer;
  uint32_t DynamicValueRelocTableOffset;
  uint16_t DynamicValueRelocTableSection;
  uint16_t Reserved2;
};


#pragma pack(4)
template <typename T>
struct load_configuration_v6 : load_configuration_v5<T> {
  T        GuardRFVerifyStackPointerFunctionPointer;
  uint32_t HotPatchTableOffset;
};
#pragma pack()

template <typename T>
struct load_configuration_v7 : load_configuration_v6<T> {
  uint32_t Reserved3;
  T        AddressOfSomeUnicodeString;
};

class PE32 {
  public:
    using pe_optional_header = pe32_optional_header;
    using pe_tls             = pe32_tls;
    using uint               = uint32_t;

    using load_configuration_t    = load_configuration<uint32_t>;
    using load_configuration_v0_t = load_configuration_v0<uint32_t>;
    using load_configuration_v1_t = load_configuration_v1<uint32_t>;
    using load_configuration_v2_t = load_configuration_v2<uint32_t>;
    using load_configuration_v3_t = load_configuration_v3<uint32_t>;
    using load_configuration_v4_t = load_configuration_v4<uint32_t>;
    using load_configuration_v5_t = load_configuration_v5<uint32_t>;
    using load_configuration_v6_t = load_configuration_v6<uint32_t>;
    using load_configuration_v7_t = load_configuration_v7<uint32_t>;


    static_assert(sizeof(load_configuration_t)    == 0x40, "");
    static_assert(sizeof(load_configuration_v0_t) == 0x48, "");
    static_assert(sizeof(load_configuration_v1_t) == 0x5c, "");
    static_assert(sizeof(load_configuration_v2_t) == 0x68, "");
    static_assert(sizeof(load_configuration_v3_t) == 0x78, "");
    static_assert(sizeof(load_configuration_v4_t) == 0x80, "");
    static_assert(sizeof(load_configuration_v5_t) == 0x90, "");
    static_assert(sizeof(load_configuration_v6_t) == 0x98, "");
    //static_assert(sizeof(LoadConfiguration_V7) == 0xA0, "");

    static const std::map<WIN_VERSION, size_t> load_configuration_sizes;
 };


class PE64 {
  public:
    using pe_optional_header = pe64_optional_header;
    using pe_tls             = pe64_tls;
    using uint               = uint64_t;

    using load_configuration_t    = load_configuration<uint64_t>;
    using load_configuration_v0_t = load_configuration_v0<uint64_t>;
    using load_configuration_v1_t = load_configuration_v1<uint64_t>;
    using load_configuration_v2_t = load_configuration_v2<uint64_t>;
    using load_configuration_v3_t = load_configuration_v3<uint64_t>;
    using load_configuration_v4_t = load_configuration_v4<uint64_t>;
    using load_configuration_v5_t = load_configuration_v5<uint64_t>;
    using load_configuration_v6_t = load_configuration_v6<uint64_t>;
    using load_configuration_v7_t = load_configuration_v7<uint64_t>;

    static_assert(sizeof(load_configuration_t)    == 0x60,  "");
    static_assert(sizeof(load_configuration_v0_t) == 0x70,  "");
    static_assert(sizeof(load_configuration_v1_t) == 0x94,  "");
    static_assert(sizeof(load_configuration_v2_t) == 0xA0,  "");
    static_assert(sizeof(load_configuration_v3_t) == 0xC0,  "");
    static_assert(sizeof(load_configuration_v4_t) == 0xD0,  "");
    static_assert(sizeof(load_configuration_v5_t) == 0xE8,  "");
    static_assert(sizeof(load_configuration_v6_t) == 0xF4,  "");
    static_assert(sizeof(load_configuration_v7_t) == 0x100, "");

    static const std::map<WIN_VERSION, size_t> load_configuration_sizes;
};



} // end namesapce ELF
}

#endif
