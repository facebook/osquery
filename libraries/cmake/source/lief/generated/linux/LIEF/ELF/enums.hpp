/* Copyright 2017 - 2021 R. Thomas
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
#ifndef LIEF_ELF_ENUMS_H_
#define LIEF_ELF_ENUMS_H_
#include "LIEF/enums.hpp"
#include "LIEF/ELF/undef.h"

namespace LIEF {
namespace ELF {


/** e_ident size and indices. */
enum _LIEF_EN(IDENTITY) {
  _LIEF_EI(EI_MAG0)       = 0,  /**< File identification index. */
  _LIEF_EI(EI_MAG1)       = 1,  /**< File identification index. */
  _LIEF_EI(EI_MAG2)       = 2,  /**< File identification index. */
  _LIEF_EI(EI_MAG3)       = 3,  /**< File identification index. */
  _LIEF_EI(EI_CLASS)      = 4,  /**< File class. */
  _LIEF_EI(EI_DATA)       = 5,  /**< Data encoding. */
  _LIEF_EI(EI_VERSION)    = 6,  /**< File version. */
  _LIEF_EI(EI_OSABI)      = 7,  /**< OS/ABI identification. */
  _LIEF_EI(EI_ABIVERSION) = 8,  /**< ABI version. */
  _LIEF_EI(EI_PAD)        = 9,  /**< Start of padding bytes. */
  _LIEF_EI(EI_NIDENT)     = 16  /**< Number of bytes in e_ident. */
};


/** Enum associated with *e_type* */
enum _LIEF_EN(E_TYPE) {
  _LIEF_EI(ET_NONE)   = 0,      /**< No file type */
  _LIEF_EI(ET_REL)    = 1,      /**< Relocatable file */
  _LIEF_EI(ET_EXEC)   = 2,      /**< Executable file */
  _LIEF_EI(ET_DYN)    = 3,      /**< Shared object file */
  _LIEF_EI(ET_CORE)   = 4,      /**< Core file */
  _LIEF_EI(ET_LOPROC) = 0xff00, /**< Beginning of processor-specific codes */
  _LIEF_EI(ET_HIPROC) = 0xffff  /**< Processor-specific */
};


/** Versioning */
enum _LIEF_EN(VERSION) {
  _LIEF_EI(EV_NONE)    = 0,
  _LIEF_EI(EV_CURRENT) = 1  /**< Default value */
};


/**
 * @brief Machine architectures
 * See current registered ELF machine architectures at:
 * http://www.sco.com/developers/gabi/latest/ch4.eheader.html
 */
enum _LIEF_EN(ARCH) {
  _LIEF_EI(EM_NONE)          = 0,  /**< No machine */
  _LIEF_EI(EM_M32)           = 1,  /**< AT&T WE 32100 */
  _LIEF_EI(EM_SPARC)         = 2,  /**< SPARC */
  _LIEF_EI(EM_386)           = 3,  /**< Intel 386 */
  _LIEF_EI(EM_68K)           = 4,  /**< Motorola 68000 */
  _LIEF_EI(EM_88K)           = 5,  /**< Motorola 88000 */
  _LIEF_EI(EM_IAMCU)         = 6,  /**< Intel MCU */
  _LIEF_EI(EM_860)           = 7,  /**< Intel 80860 */
  _LIEF_EI(EM_MIPS)          = 8,  /**< MIPS R3000 */
  _LIEF_EI(EM_S370)          = 9,  /**< IBM System/370 */
  _LIEF_EI(EM_MIPS_RS3_LE)   = 10, /**< MIPS RS3000 Little-endian */
  _LIEF_EI(EM_PARISC)        = 15, /**< Hewlett-Packard PA-RISC */
  _LIEF_EI(EM_VPP500)        = 17, /**< Fujitsu VPP500 */
  _LIEF_EI(EM_SPARC32PLUS)   = 18, /**< Enhanced instruction set SPARC */
  _LIEF_EI(EM_960)           = 19, /**< Intel 80960 */
  _LIEF_EI(EM_PPC)           = 20, /**< PowerPC */
  _LIEF_EI(EM_PPC64)         = 21, /**< PowerPC64 */
  _LIEF_EI(EM_S390)          = 22, /**< IBM System/390 */
  _LIEF_EI(EM_SPU)           = 23, /**< IBM SPU/SPC */
  _LIEF_EI(EM_V800)          = 36, /**< NEC V800 */
  _LIEF_EI(EM_FR20)          = 37, /**< Fujitsu FR20 */
  _LIEF_EI(EM_RH32)          = 38, /**< TRW RH-32 */
  _LIEF_EI(EM_RCE)           = 39, /**< Motorola RCE */
  _LIEF_EI(EM_ARM)           = 40, /**< ARM */
  _LIEF_EI(EM_ALPHA)         = 41, /**< DEC Alpha */
  _LIEF_EI(EM_SH)            = 42, /**< Hitachi SH */
  _LIEF_EI(EM_SPARCV9)       = 43, /**< SPARC V9 */
  _LIEF_EI(EM_TRICORE)       = 44, /**< Siemens TriCore */
  _LIEF_EI(EM_ARC)           = 45, /**< Argonaut RISC Core */
  _LIEF_EI(EM_H8_300)        = 46, /**< Hitachi H8/300 */
  _LIEF_EI(EM_H8_300H)       = 47, /**< Hitachi H8/300H */
  _LIEF_EI(EM_H8S)           = 48, /**< Hitachi H8S */
  _LIEF_EI(EM_H8_500)        = 49, /**< Hitachi H8/500 */
  _LIEF_EI(EM_IA_64)         = 50, /**< Intel IA-64 processor architecture */
  _LIEF_EI(EM_MIPS_X)        = 51, /**< Stanford MIPS-X */
  _LIEF_EI(EM_COLDFIRE)      = 52, /**< Motorola ColdFire */
  _LIEF_EI(EM_68HC12)        = 53, /**< Motorola M68HC12 */
  _LIEF_EI(EM_MMA)           = 54, /**< Fujitsu MMA Multimedia Accelerator */
  _LIEF_EI(EM_PCP)           = 55, /**< Siemens PCP */
  _LIEF_EI(EM_NCPU)          = 56, /**< Sony nCPU embedded RISC processor */
  _LIEF_EI(EM_NDR1)          = 57, /**< Denso NDR1 microprocessor */
  _LIEF_EI(EM_STARCORE)      = 58, /**< Motorola Star*Core processor */
  _LIEF_EI(EM_ME16)          = 59, /**< Toyota ME16 processor */
  _LIEF_EI(EM_ST100)         = 60, /**< STMicroelectronics ST100 processor */
  _LIEF_EI(EM_TINYJ)         = 61, /**< Advanced Logic Corp. TinyJ embedded processor family */
  _LIEF_EI(EM_X86_64)        = 62, /**< AMD x86-64 architecture */
  _LIEF_EI(EM_PDSP)          = 63, /**< Sony DSP Processor */
  _LIEF_EI(EM_PDP10)         = 64, /**< Digital Equipment Corp. PDP-10 */
  _LIEF_EI(EM_PDP11)         = 65, /**< Digital Equipment Corp. PDP-11 */
  _LIEF_EI(EM_FX66)          = 66, /**< Siemens FX66 microcontroller */
  _LIEF_EI(EM_ST9PLUS)       = 67, /**< STMicroelectronics ST9+ 8/16 bit microcontroller */
  _LIEF_EI(EM_ST7)           = 68, /**< STMicroelectronics ST7 8-bit microcontroller */
  _LIEF_EI(EM_68HC16)        = 69, /**< Motorola MC68HC16 Microcontroller */
  _LIEF_EI(EM_68HC11)        = 70, /**< Motorola MC68HC11 Microcontroller */
  _LIEF_EI(EM_68HC08)        = 71, /**< Motorola MC68HC08 Microcontroller */
  _LIEF_EI(EM_68HC05)        = 72, /**< Motorola MC68HC05 Microcontroller */
  _LIEF_EI(EM_SVX)           = 73, /**< Silicon Graphics SVx */
  _LIEF_EI(EM_ST19)          = 74, /**< STMicroelectronics ST19 8-bit microcontroller */
  _LIEF_EI(EM_VAX)           = 75, /**< Digital VAX */
  _LIEF_EI(EM_CRIS)          = 76, /**< Axis Communications 32-bit embedded processor */
  _LIEF_EI(EM_JAVELIN)       = 77, /**< Infineon Technologies 32-bit embedded processor */
  _LIEF_EI(EM_FIREPATH)      = 78, /**< Element 14 64-bit DSP Processor */
  _LIEF_EI(EM_ZSP)           = 79, /**< LSI Logic 16-bit DSP Processor */
  _LIEF_EI(EM_MMIX)          = 80, /**< Donald Knuth's educational 64-bit processor */
  _LIEF_EI(EM_HUANY)         = 81, /**< Harvard University machine-independent object files */
  _LIEF_EI(EM_PRISM)         = 82, /**< SiTera Prism */
  _LIEF_EI(EM_AVR)           = 83, /**< Atmel AVR 8-bit microcontroller */
  _LIEF_EI(EM_FR30)          = 84, /**< Fujitsu FR30 */
  _LIEF_EI(EM_D10V)          = 85, /**< Mitsubishi D10V */
  _LIEF_EI(EM_D30V)          = 86, /**< Mitsubishi D30V */
  _LIEF_EI(EM_V850)          = 87, /**< NEC v850 */
  _LIEF_EI(EM_M32R)          = 88, /**< Mitsubishi M32R */
  _LIEF_EI(EM_MN10300)       = 89, /**< Matsushita MN10300 */
  _LIEF_EI(EM_MN10200)       = 90, /**< Matsushita MN10200 */
  _LIEF_EI(EM_PJ)            = 91, /**< picoJava */
  _LIEF_EI(EM_OPENRISC)      = 92, /**< OpenRISC 32-bit embedded processor */
  _LIEF_EI(EM_ARC_COMPACT)   = 93, /**< ARC International ARCompact processor (old spelling/synonym: EM_ARC_A5) */
  _LIEF_EI(EM_XTENSA)        = 94,  /**< Tensilica Xtensa Architecture */
  _LIEF_EI(EM_VIDEOCORE)     = 95,  /**< Alphamosaic VideoCore processor */
  _LIEF_EI(EM_TMM_GPP)       = 96,  /**< Thompson Multimedia General Purpose Processor */
  _LIEF_EI(EM_NS32K)         = 97,  /**< National Semiconductor 32000 series */
  _LIEF_EI(EM_TPC)           = 98,  /**< Tenor Network TPC processor */
  _LIEF_EI(EM_SNP1K)         = 99,  /**< Trebia SNP 1000 processor */
  _LIEF_EI(EM_ST200)         = 100, /**< STMicroelectronics (www.st.com) ST200 */
  _LIEF_EI(EM_IP2K)          = 101, /**< Ubicom IP2xxx microcontroller family */
  _LIEF_EI(EM_MAX)           = 102, /**< MAX Processor */
  _LIEF_EI(EM_CR)            = 103, /**< National Semiconductor CompactRISC microprocessor */
  _LIEF_EI(EM_F2MC16)        = 104, /**< Fujitsu F2MC16 */
  _LIEF_EI(EM_MSP430)        = 105, /**< Texas Instruments embedded microcontroller msp430 */
  _LIEF_EI(EM_BLACKFIN)      = 106, /**< Analog Devices Blackfin (DSP) processor */
  _LIEF_EI(EM_SE_C33)        = 107, /**< S1C33 Family of Seiko Epson processors */
  _LIEF_EI(EM_SEP)           = 108, /**< Sharp embedded microprocessor */
  _LIEF_EI(EM_ARCA)          = 109, /**< Arca RISC Microprocessor */
  _LIEF_EI(EM_UNICORE)       = 110, /**< Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University */
  _LIEF_EI(EM_EXCESS)        = 111, /**< eXcess: 16/32/64-bit configurable embedded CPU */
  _LIEF_EI(EM_DXP)           = 112, /**< Icera Semiconductor Inc. Deep Execution Processor */
  _LIEF_EI(EM_ALTERA_NIOS2)  = 113, /**< Altera Nios II soft-core processor */
  _LIEF_EI(EM_CRX)           = 114, /**< National Semiconductor CompactRISC CRX */
  _LIEF_EI(EM_XGATE)         = 115, /**< Motorola XGATE embedded processor */
  _LIEF_EI(EM_C166)          = 116, /**< Infineon C16x/XC16x processor */
  _LIEF_EI(EM_M16C)          = 117, /**< Renesas M16C series microprocessors */
  _LIEF_EI(EM_DSPIC30F)      = 118, /**< Microchip Technology dsPIC30F Digital Signal */
  /* Controller */
  _LIEF_EI(EM_CE)            = 119, /**< Freescale Communication Engine RISC core */
  _LIEF_EI(EM_M32C)          = 120, /**< Renesas M32C series microprocessors */
  _LIEF_EI(EM_TSK3000)       = 131, /**< Altium TSK3000 core */
  _LIEF_EI(EM_RS08)          = 132, /**< Freescale RS08 embedded processor */
  _LIEF_EI(EM_SHARC)         = 133, /**< Analog Devices SHARC family of 32-bit DSP */
  /* processors */
  _LIEF_EI(EM_ECOG2)         = 134, /**< Cyan Technology eCOG2 microprocessor */
  _LIEF_EI(EM_SCORE7)        = 135, /**< Sunplus S+core7 RISC processor */
  _LIEF_EI(EM_DSP24)         = 136, /**< New Japan Radio (NJR) 24-bit DSP Processor */
  _LIEF_EI(EM_VIDEOCORE3)    = 137, /**< Broadcom VideoCore III processor */
  _LIEF_EI(EM_LATTICEMICO32) = 138, /**< RISC processor for Lattice FPGA architecture */
  _LIEF_EI(EM_SE_C17)        = 139, /**< Seiko Epson C17 family */
  _LIEF_EI(EM_TI_C6000)      = 140, /**< The Texas Instruments TMS320C6000 DSP family */
  _LIEF_EI(EM_TI_C2000)      = 141, /**< The Texas Instruments TMS320C2000 DSP family */
  _LIEF_EI(EM_TI_C5500)      = 142, /**< The Texas Instruments TMS320C55x DSP family */
  _LIEF_EI(EM_MMDSP_PLUS)    = 160, /**< STMicroelectronics 64bit VLIW Data Signal Processor */
  _LIEF_EI(EM_CYPRESS_M8C)   = 161, /**< Cypress M8C microprocessor */
  _LIEF_EI(EM_R32C)          = 162, /**< Renesas R32C series microprocessors */
  _LIEF_EI(EM_TRIMEDIA)      = 163, /**< NXP Semiconductors TriMedia architecture family */
  _LIEF_EI(EM_HEXAGON)       = 164, /**< Qualcomm Hexagon processor */
  _LIEF_EI(EM_8051)          = 165, /**< Intel 8051 and variants */
  _LIEF_EI(EM_STXP7X)        = 166, /**< STMicroelectronics STxP7x family of configurable */
  /* and extensible RISC processors */
  _LIEF_EI(EM_NDS32)         = 167, /* Andes Technology compact code size embedded RISC */
  /* processor family */
  _LIEF_EI(EM_ECOG1)         = 168, /**< Cyan Technology eCOG1X family */
  _LIEF_EI(EM_ECOG1X)        = 168, /**< Cyan Technology eCOG1X family */
  _LIEF_EI(EM_MAXQ30)        = 169, /**< Dallas Semiconductor MAXQ30 Core Micro-controllers */
  _LIEF_EI(EM_XIMO16)        = 170, /**< New Japan Radio (NJR) 16-bit DSP Processor */
  _LIEF_EI(EM_MANIK)         = 171, /**< M2000 Reconfigurable RISC Microprocessor */
  _LIEF_EI(EM_CRAYNV2)       = 172, /**< Cray Inc. NV2 vector architecture */
  _LIEF_EI(EM_RX)            = 173, /**< Renesas RX family */
  _LIEF_EI(EM_METAG)         = 174, /**< Imagination Technologies META processor */
  /* architecture */
  _LIEF_EI(EM_MCST_ELBRUS)   = 175, /**< MCST Elbrus general purpose hardware architecture */
  _LIEF_EI(EM_ECOG16)        = 176, /**< Cyan Technology eCOG16 family */
  _LIEF_EI(EM_CR16)          = 177, /**< National Semiconductor CompactRISC CR16 16-bit */
  /* microprocessor */
  _LIEF_EI(EM_ETPU)          = 178, /**< Freescale Extended Time Processing Unit */
  _LIEF_EI(EM_SLE9X)         = 179, /**< Infineon Technologies SLE9X core */
  _LIEF_EI(EM_L10M)          = 180, /**< Intel L10M */
  _LIEF_EI(EM_K10M)          = 181, /**< Intel K10M */
  _LIEF_EI(EM_AARCH64)       = 183, /**< ARM AArch64 */
  _LIEF_EI(EM_AVR32)         = 185, /**< Atmel Corporation 32-bit microprocessor family */
  _LIEF_EI(EM_STM8)          = 186, /**< STMicroeletronics STM8 8-bit microcontroller */
  _LIEF_EI(EM_TILE64)        = 187, /**< Tilera TILE64 multicore architecture family */
  _LIEF_EI(EM_TILEPRO)       = 188, /**< Tilera TILEPro multicore architecture family */
  _LIEF_EI(EM_CUDA)          = 190, /**< NVIDIA CUDA architecture */
  _LIEF_EI(EM_TILEGX)        = 191, /**< Tilera TILE-Gx multicore architecture family */
  _LIEF_EI(EM_CLOUDSHIELD)   = 192, /**< CloudShield architecture family */
  _LIEF_EI(EM_COREA_1ST)     = 193, /**< KIPO-KAIST Core-A 1st generation processor family */
  _LIEF_EI(EM_COREA_2ND)     = 194, /**< KIPO-KAIST Core-A 2nd generation processor family */
  _LIEF_EI(EM_ARC_COMPACT2)  = 195, /**< Synopsys ARCompact V2 */
  _LIEF_EI(EM_OPEN8)         = 196, /**< Open8 8-bit RISC soft processor core */
  _LIEF_EI(EM_RL78)          = 197, /**< Renesas RL78 family */
  _LIEF_EI(EM_VIDEOCORE5)    = 198, /**< Broadcom VideoCore V processor */
  _LIEF_EI(EM_78KOR)         = 199, /**< Renesas 78KOR family */
  _LIEF_EI(EM_56800EX)       = 200, /**< Freescale 56800EX Digital Signal Controller (DSC) */
  _LIEF_EI(EM_BA1)           = 201, /**< Beyond BA1 CPU architecture */
  _LIEF_EI(EM_BA2)           = 202, /**< Beyond BA2 CPU architecture */
  _LIEF_EI(EM_XCORE)         = 203, /**< XMOS xCORE processor family */
  _LIEF_EI(EM_MCHP_PIC)      = 204, /**< Microchip 8-bit PIC(r) family */
  _LIEF_EI(EM_INTEL205)      = 205, /**< Reserved by Intel */
  _LIEF_EI(EM_INTEL206)      = 206, /**< Reserved by Intel */
  _LIEF_EI(EM_INTEL207)      = 207, /**< Reserved by Intel */
  _LIEF_EI(EM_INTEL208)      = 208, /**< Reserved by Intel */
  _LIEF_EI(EM_INTEL209)      = 209, /**< Reserved by Intel */
  _LIEF_EI(EM_KM32)          = 210, /**< KM211 KM32 32-bit processor */
  _LIEF_EI(EM_KMX32)         = 211, /**< KM211 KMX32 32-bit processor */
  _LIEF_EI(EM_KMX16)         = 212, /**< KM211 KMX16 16-bit processor */
  _LIEF_EI(EM_KMX8)          = 213, /**< KM211 KMX8 8-bit processor */
  _LIEF_EI(EM_KVARC)         = 214, /**< KM211 KVARC processor */
  _LIEF_EI(EM_CDP)           = 215, /**< Paneve CDP architecture family */
  _LIEF_EI(EM_COGE)          = 216, /**< Cognitive Smart Memory Processor */
  _LIEF_EI(EM_COOL)          = 217, /**< iCelero CoolEngine */
  _LIEF_EI(EM_NORC)          = 218, /**< Nanoradio Optimized RISC */
  _LIEF_EI(EM_CSR_KALIMBA)   = 219, /**< CSR Kalimba architecture family */
  _LIEF_EI(EM_AMDGPU)        = 224, /**< AMD GPU architecture */
  _LIEF_EI(EM_RISCV)         = 243, /**< RISC-V */
  _LIEF_EI(EM_BPF)           = 247  /**< eBPF Filter */
};


/** Object file classes. */
enum _LIEF_EN(ELF_CLASS) {
  _LIEF_EI(ELFCLASSNONE) = 0, /**< Unknown */
  _LIEF_EI(ELFCLASS32)   = 1, /**< 32-bit object file */
  _LIEF_EI(ELFCLASS64)   = 2  /**< 64-bit object file */
};

/** Object file byte orderings. */
enum _LIEF_EN(ELF_DATA) {
  _LIEF_EI(ELFDATANONE) = 0, /**< Invalid data encoding. */
  _LIEF_EI(ELFDATA2LSB) = 1, /**< Little-endian object file */
  _LIEF_EI(ELFDATA2MSB) = 2  /**< Big-endian object file */
};

/** OS ABI identification. */
enum _LIEF_EN(OS_ABI) {
  _LIEF_EI(ELFOSABI_SYSTEMV)      = 0,  /**< UNIX System V ABI */
  _LIEF_EI(ELFOSABI_HPUX)         = 1,  /**< HP-UX operating system */
  _LIEF_EI(ELFOSABI_NETBSD)       = 2,  /**< NetBSD */
  _LIEF_EI(ELFOSABI_GNU)          = 3,  /**< GNU/Linux */
  _LIEF_EI(ELFOSABI_LINUX)        = 3,  /**< Historical alias for ELFOSABI_GNU. */
  _LIEF_EI(ELFOSABI_HURD)         = 4,  /**< GNU/Hurd */
  _LIEF_EI(ELFOSABI_SOLARIS)      = 6,  /**< Solaris */
  _LIEF_EI(ELFOSABI_AIX)          = 7,  /**< AIX */
  _LIEF_EI(ELFOSABI_IRIX)         = 8,  /**< IRIX */
  _LIEF_EI(ELFOSABI_FREEBSD)      = 9,  /**< FreeBSD */
  _LIEF_EI(ELFOSABI_TRU64)        = 10, /**< TRU64 UNIX */
  _LIEF_EI(ELFOSABI_MODESTO)      = 11, /**< Novell Modesto */
  _LIEF_EI(ELFOSABI_OPENBSD)      = 12, /**< OpenBSD */
  _LIEF_EI(ELFOSABI_OPENVMS)      = 13, /**< OpenVMS */
  _LIEF_EI(ELFOSABI_NSK)          = 14, /**< Hewlett-Packard Non-Stop Kernel */
  _LIEF_EI(ELFOSABI_AROS)         = 15, /**< AROS */
  _LIEF_EI(ELFOSABI_FENIXOS)      = 16, /**< FenixOS */
  _LIEF_EI(ELFOSABI_CLOUDABI)     = 17, /**< Nuxi CloudABI */
  _LIEF_EI(ELFOSABI_C6000_ELFABI) = 64, /**< Bare-metal TMS320C6000 */
  _LIEF_EI(ELFOSABI_AMDGPU_HSA)   = 64, /**< AMD HSA runtime */
  _LIEF_EI(ELFOSABI_C6000_LINUX)  = 65, /**< Linux TMS320C6000 */
  _LIEF_EI(ELFOSABI_ARM)          = 97, /**< ARM */
  _LIEF_EI(ELFOSABI_STANDALONE)   = 255 /**< Standalone (embedded) application */
};

/* ELF Relocations */

#define ELF_RELOC(name, value) _LIEF_EI(name) = value,

/** x86_64 relocations. */
enum _LIEF_EN(RELOC_x86_64) {
   #include "LIEF/ELF/Relocations/x86_64.def"
};

/** i386 relocations. */
enum  RELOC_i386 {
   #include "LIEF/ELF/Relocations/i386.def"
};

/* ELF Relocation types for PPC32 */
enum _LIEF_EN(RELOC_POWERPC32) {
   #include "LIEF/ELF/Relocations/PowerPC.def"
};

/* ELF Relocation types for PPC64 */
enum _LIEF_EN(RELOC_POWERPC64) {
   #include "LIEF/ELF/Relocations/PowerPC64.def"
};

/* ELF Relocation types for AArch64 */
enum _LIEF_EN(RELOC_AARCH64) {
   #include "LIEF/ELF/Relocations/AArch64.def"
};

/* ELF Relocation types for ARM */
enum _LIEF_EN(RELOC_ARM) {
  #include "LIEF/ELF/Relocations/ARM.def"
};

/* ELF Relocation types for Mips */
enum _LIEF_EN(RELOC_MIPS) {
  #include "LIEF/ELF/Relocations/Mips.def"
};

/* ELF Relocation types for Hexagon */
enum _LIEF_EN(RELOC_HEXAGON) {
  #include "LIEF/ELF/Relocations/Hexagon.def"
};

/* ELF Relocation types for S390/zSeries */
enum _LIEF_EN(RELOC_SYSTEMZ) {
  #include "LIEF/ELF/Relocations/SystemZ.def"
};

/* ELF Relocation type for Sparc. */
enum _LIEF_EN(RELOC_SPARC) {
  #include "LIEF/ELF/Relocations/Sparc.def"
};

#undef ELF_RELOC

/* Specific e_flags for PPC64 */
enum _LIEF_EN(PPC64_EFLAGS) {
  /* e_flags bits specifying ABI: */
  /* 1 for original ABI using function descriptors, */
  /* 2 for revised ABI without function descriptors, */
  /* 0 for unspecified or not using any features affected by the differences. */
  _LIEF_EI(EF_PPC64_ABI) = 3
};

/* ARM Specific e_flags */
enum _LIEF_EN(ARM_EFLAGS) {
  _LIEF_EI(EF_ARM_SOFT_FLOAT)   = 0x00000200U,
  _LIEF_EI(EF_ARM_VFP_FLOAT)    = 0x00000400U,
  _LIEF_EI(EF_ARM_EABI_UNKNOWN) = 0x00000000U,
  _LIEF_EI(EF_ARM_EABI_VER1)    = 0x01000000U,
  _LIEF_EI(EF_ARM_EABI_VER2)    = 0x02000000U,
  _LIEF_EI(EF_ARM_EABI_VER3)    = 0x03000000U,
  _LIEF_EI(EF_ARM_EABI_VER4)    = 0x04000000U,
  _LIEF_EI(EF_ARM_EABI_VER5)    = 0x05000000U,
  _LIEF_EI(EF_ARM_EABIMASK)     = 0xFF000000U
};

/* Mips Specific e_flags */
enum _LIEF_EN(MIPS_EFLAGS) {
  _LIEF_EI(EF_MIPS_NOREORDER) = 0x00000001, /* Don't reorder instructions */
  _LIEF_EI(EF_MIPS_PIC)       = 0x00000002, /* Position independent code */
  _LIEF_EI(EF_MIPS_CPIC)      = 0x00000004, /* Call object with Position independent code */
  _LIEF_EI(EF_MIPS_ABI2)      = 0x00000020, /* File uses N32 ABI */
  _LIEF_EI(EF_MIPS_32BITMODE) = 0x00000100, /* Code compiled for a 64-bit machine */
  /* in 32-bit mode */
  _LIEF_EI(EF_MIPS_FP64)      = 0x00000200, /* Code compiled for a 32-bit machine */
  /* but uses 64-bit FP registers */
  _LIEF_EI(EF_MIPS_NAN2008)   = 0x00000400, /* Uses IEE 754-2008 NaN encoding */

  /* ABI flags */
  _LIEF_EI(EF_MIPS_ABI_O32)    = 0x00001000, /* This file follows the first MIPS 32 bit ABI */
  _LIEF_EI(EF_MIPS_ABI_O64)    = 0x00002000, /* O32 ABI extended for 64-bit architecture. */
  _LIEF_EI(EF_MIPS_ABI_EABI32) = 0x00003000, /* EABI in 32 bit mode. */
  _LIEF_EI(EF_MIPS_ABI_EABI64) = 0x00004000, /* EABI in 64 bit mode. */
  _LIEF_EI(EF_MIPS_ABI)        = 0x0000f000, /* Mask for selecting EF_MIPS_ABI_ variant. */

  /* MIPS machine variant */
  _LIEF_EI(EF_MIPS_MACH_3900)    = 0x00810000, /* Toshiba R3900 */
  _LIEF_EI(EF_MIPS_MACH_4010)    = 0x00820000, /* LSI R4010 */
  _LIEF_EI(EF_MIPS_MACH_4100)    = 0x00830000, /* NEC VR4100 */
  _LIEF_EI(EF_MIPS_MACH_4650)    = 0x00850000, /* MIPS R4650 */
  _LIEF_EI(EF_MIPS_MACH_4120)    = 0x00870000, /* NEC VR4120 */
  _LIEF_EI(EF_MIPS_MACH_4111)    = 0x00880000, /* NEC VR4111/VR4181 */
  _LIEF_EI(EF_MIPS_MACH_SB1)     = 0x008a0000, /* Broadcom SB-1 */
  _LIEF_EI(EF_MIPS_MACH_OCTEON)  = 0x008b0000, /* Cavium Networks Octeon */
  _LIEF_EI(EF_MIPS_MACH_XLR)     = 0x008c0000, /* RMI Xlr */
  _LIEF_EI(EF_MIPS_MACH_OCTEON2) = 0x008d0000, /* Cavium Networks Octeon2 */
  _LIEF_EI(EF_MIPS_MACH_OCTEON3) = 0x008e0000, /* Cavium Networks Octeon3 */
  _LIEF_EI(EF_MIPS_MACH_5400)    = 0x00910000, /* NEC VR5400 */
  _LIEF_EI(EF_MIPS_MACH_5900)    = 0x00920000, /* MIPS R5900 */
  _LIEF_EI(EF_MIPS_MACH_5500)    = 0x00980000, /* NEC VR5500 */
  _LIEF_EI(EF_MIPS_MACH_9000)    = 0x00990000, /* Unknown */
  _LIEF_EI(EF_MIPS_MACH_LS2E)    = 0x00a00000, /* ST Microelectronics Loongson 2E */
  _LIEF_EI(EF_MIPS_MACH_LS2F)    = 0x00a10000, /* ST Microelectronics Loongson 2F */
  _LIEF_EI(EF_MIPS_MACH_LS3A)    = 0x00a20000, /* Loongson 3A */
  _LIEF_EI(EF_MIPS_MACH)         = 0x00ff0000, /* EF_MIPS_MACH_xxx selection mask */

  /* ARCH_ASE */
  _LIEF_EI(EF_MIPS_MICROMIPS)     = 0x02000000, /* microMIPS */
  _LIEF_EI(EF_MIPS_ARCH_ASE_M16)  = 0x04000000, /* Has Mips-16 ISA extensions */
  _LIEF_EI(EF_MIPS_ARCH_ASE_MDMX) = 0x08000000, /* Has MDMX multimedia extensions */
  _LIEF_EI(EF_MIPS_ARCH_ASE)      = 0x0f000000, /* Mask for EF_MIPS_ARCH_ASE_xxx flags */

  /* ARCH */
  _LIEF_EI(EF_MIPS_ARCH_1)    = 0x00000000, /* MIPS1 instruction set */
  _LIEF_EI(EF_MIPS_ARCH_2)    = 0x10000000, /* MIPS2 instruction set */
  _LIEF_EI(EF_MIPS_ARCH_3)    = 0x20000000, /* MIPS3 instruction set */
  _LIEF_EI(EF_MIPS_ARCH_4)    = 0x30000000, /* MIPS4 instruction set */
  _LIEF_EI(EF_MIPS_ARCH_5)    = 0x40000000, /* MIPS5 instruction set */
  _LIEF_EI(EF_MIPS_ARCH_32)   = 0x50000000, /* MIPS32 instruction set per linux not elf.h */
  _LIEF_EI(EF_MIPS_ARCH_64)   = 0x60000000, /* MIPS64 instruction set per linux not elf.h */
  _LIEF_EI(EF_MIPS_ARCH_32R2) = 0x70000000, /* mips32r2, mips32r3, mips32r5 */
  _LIEF_EI(EF_MIPS_ARCH_64R2) = 0x80000000, /* mips64r2, mips64r3, mips64r5 */
  _LIEF_EI(EF_MIPS_ARCH_32R6) = 0x90000000, /* mips32r6 */
  _LIEF_EI(EF_MIPS_ARCH_64R6) = 0xa0000000, /* mips64r6 */
  _LIEF_EI(EF_MIPS_ARCH)      = 0xf0000000  /* Mask for applying EF_MIPS_ARCH_ variant */
};

/* Hexagon Specific e_flags */
/* Release 5 ABI */
enum _LIEF_EN(HEXAGON_EFLAGS) {
  /* Object processor version flags, bits[3:0] */
  _LIEF_EI(EF_HEXAGON_MACH_V2)      = 0x00000001,   /* Hexagon V2 */
  _LIEF_EI(EF_HEXAGON_MACH_V3)      = 0x00000002,   /* Hexagon V3 */
  _LIEF_EI(EF_HEXAGON_MACH_V4)      = 0x00000003,   /* Hexagon V4 */
  _LIEF_EI(EF_HEXAGON_MACH_V5)      = 0x00000004,   /* Hexagon V5 */

  /* Highest ISA version flags */
  _LIEF_EI(EF_HEXAGON_ISA_MACH)     = 0x00000000,   /* Same as specified in bits[3:0] */
  /* of e_flags */
  _LIEF_EI(EF_HEXAGON_ISA_V2)       = 0x00000010,   /* Hexagon V2 ISA */
  _LIEF_EI(EF_HEXAGON_ISA_V3)       = 0x00000020,   /* Hexagon V3 ISA */
  _LIEF_EI(EF_HEXAGON_ISA_V4)       = 0x00000030,   /* Hexagon V4 ISA */
  _LIEF_EI(EF_HEXAGON_ISA_V5)       = 0x00000040    /* Hexagon V5 ISA */
};




/** Special section indices. */
enum _LIEF_EN(SYMBOL_SECTION_INDEX) {
  _LIEF_EI(SHN_UNDEF)     = 0,      /**< Undefined, missing, irrelevant, or meaningless */
  _LIEF_EI(SHN_LORESERVE) = 0xff00, /**< Lowest reserved index */
  _LIEF_EI(SHN_LOPROC)    = 0xff00, /**< Lowest processor-specific index */
  _LIEF_EI(SHN_HIPROC)    = 0xff1f, /**< Highest processor-specific index */
  _LIEF_EI(SHN_LOOS)      = 0xff20, /**< Lowest operating system-specific index */
  _LIEF_EI(SHN_HIOS)      = 0xff3f, /**< Highest operating system-specific index */
  _LIEF_EI(SHN_ABS)       = 0xfff1, /**< Symbol has absolute value; does not need relocation */
  _LIEF_EI(SHN_COMMON)    = 0xfff2, /**< FORTRAN COMMON or C external global variables */
  _LIEF_EI(SHN_XINDEX)    = 0xffff, /**< Mark that the index is >= SHN_LORESERVE */
  _LIEF_EI(SHN_HIRESERVE) = 0xffff  /**< Highest reserved index */
};

/** Section types. */
enum _LIEF_EN(ELF_SECTION_TYPES) {
  _LIEF_EI(SHT_NULL)                = 0,  /**< No associated section (inactive entry). */
  _LIEF_EI(SHT_PROGBITS)            = 1,  /**< Program-defined contents. */
  _LIEF_EI(SHT_SYMTAB)              = 2,  /**< Symbol table. */
  _LIEF_EI(SHT_STRTAB)              = 3,  /**< String table. */
  _LIEF_EI(SHT_RELA)                = 4,  /**< Relocation entries; explicit addends. */
  _LIEF_EI(SHT_HASH)                = 5,  /**< Symbol hash table. */
  _LIEF_EI(SHT_DYNAMIC)             = 6,  /**< Information for dynamic linking. */
  _LIEF_EI(SHT_NOTE)                = 7,  /**< Information about the file. */
  _LIEF_EI(SHT_NOBITS)              = 8,  /**< Data occupies no space in the file. */
  _LIEF_EI(SHT_REL)                 = 9,  /**< Relocation entries; no explicit addends. */
  _LIEF_EI(SHT_SHLIB)               = 10, /**< Reserved. */
  _LIEF_EI(SHT_DYNSYM)              = 11, /**< Symbol table. */
  _LIEF_EI(SHT_INIT_ARRAY)          = 14, /**< Pointers to initialization functions. */
  _LIEF_EI(SHT_FINI_ARRAY)          = 15, /**< Pointers to termination functions. */
  _LIEF_EI(SHT_PREINIT_ARRAY)       = 16, /**< Pointers to pre-init functions. */
  _LIEF_EI(SHT_GROUP)               = 17, /**< Section group. */
  _LIEF_EI(SHT_SYMTAB_SHNDX)        = 18, /**< Indices for SHN_XINDEX entries. */
  _LIEF_EI(SHT_LOOS)                = 0x60000000, /**< Lowest operating system-specific type. */
  _LIEF_EI(SHT_ANDROID_REL)         = 0x60000001, /**< Packed relocations (Android specific). */
  _LIEF_EI(SHT_ANDROID_RELA)        = 0x60000002, /**< Packed relocations (Android specific). */
  _LIEF_EI(SHT_LLVM_ADDRSIG)        = 0x6fff4c03, /**< This section is used to mark symbols as address-significant. */
  _LIEF_EI(SHT_RELR)                = 0x6fffff00, /**< New relr relocations (Android specific). */
  _LIEF_EI(SHT_GNU_ATTRIBUTES)      = 0x6ffffff5, /**< Object attributes. */
  _LIEF_EI(SHT_GNU_HASH)            = 0x6ffffff6, /**< GNU-style hash table. */
  _LIEF_EI(SHT_GNU_verdef)          = 0x6ffffffd, /**< GNU version definitions. */
  _LIEF_EI(SHT_GNU_verneed)         = 0x6ffffffe, /**< GNU version references. */
  _LIEF_EI(SHT_GNU_versym)          = 0x6fffffff, /**< GNU symbol versions table. */
  _LIEF_EI(SHT_HIOS)                = 0x6fffffff, /**< Highest operating system-specific type. */
  _LIEF_EI(SHT_LOPROC)              = 0x70000000, /**< Lowest processor arch-specific type. */
  _LIEF_EI(SHT_ARM_EXIDX)           = 0x70000001U, /**< Exception Index table */
  _LIEF_EI(SHT_ARM_PREEMPTMAP)      = 0x70000002U, /**< BPABI DLL dynamic linking pre-emption map */
  _LIEF_EI(SHT_ARM_ATTRIBUTES)      = 0x70000003U, /**<  Object file compatibility attributes */
  _LIEF_EI(SHT_ARM_DEBUGOVERLAY)    = 0x70000004U,
  _LIEF_EI(SHT_ARM_OVERLAYSECTION)  = 0x70000005U,
  _LIEF_EI(SHT_HEX_ORDERED)         = 0x70000000, /**< Link editor is to sort the entries in */

  /* this section based on their sizes */
  _LIEF_EI(SHT_X86_64_UNWIND)       = 0x70000001, /**< Unwind information */
  _LIEF_EI(SHT_MIPS_REGINFO)        = 0x70000006, /**< Register usage information */
  _LIEF_EI(SHT_MIPS_OPTIONS)        = 0x7000000d, /**< General options */
  _LIEF_EI(SHT_MIPS_ABIFLAGS)       = 0x7000002a, /**< ABI information. */

  _LIEF_EI(SHT_HIPROC)              = 0x7fffffff, /**< Highest processor arch-specific type. */
  _LIEF_EI(SHT_LOUSER)              = 0x80000000, /**< Lowest type reserved for applications. */
  _LIEF_EI(SHT_HIUSER)              = 0xffffffff  /**< Highest type reserved for applications. */
};



/** Section flags. */
enum _LIEF_EN(ELF_SECTION_FLAGS) {
  _LIEF_EI(SHF_NONE)             = 0x0,
  _LIEF_EI(SHF_WRITE)            = 0x1,         /**< Section data should be writable during execution. */
  _LIEF_EI(SHF_ALLOC)            = 0x2,         /**< Section occupies memory during program execution. */
  _LIEF_EI(SHF_EXECINSTR)        = 0x4,         /**< Section contains executable machine instructions. */
  _LIEF_EI(SHF_MERGE)            = 0x10,        /**< The data in this section may be merged. */
  _LIEF_EI(SHF_STRINGS)          = 0x20,        /**< The data in this section is null-terminated strings. */
  _LIEF_EI(SHF_INFO_LINK)        = 0x40U,       /**< A field in this section holds a section header table index. */
  _LIEF_EI(SHF_LINK_ORDER)       = 0x80U,       /**< Adds special ordering requirements for link editors. */
  _LIEF_EI(SHF_OS_NONCONFORMING) = 0x100U,      /**< This section requires special OS-specific processing to avoid incorrect behavior */
  _LIEF_EI(SHF_GROUP)            = 0x200U,      /**< This section is a member of a section group. */
  _LIEF_EI(SHF_TLS)              = 0x400U,      /**< This section holds Thread-Local Storage. */
  _LIEF_EI(SHF_EXCLUDE)          = 0x80000000U, /**< This section is excluded from the final executable or shared library. */
  /* Start of target-specific flags. */

  /* XCORE_SHF_CP_SECTION - All sections with the "c" flag are grouped
   * together by the linker to form the constant pool and the cp register is
   * set to the start of the constant pool by the boot code.
   */
  _LIEF_EI(XCORE_SHF_CP_SECTION) = 0x800U,

  /* XCORE_SHF_DP_SECTION - All sections with the "d" flag are grouped
   * together by the linker to form the data section and the dp register is
   * set to the start of the section by the boot code.
   */
  _LIEF_EI(XCORE_SHF_DP_SECTION) = 0x1000U,
  _LIEF_EI(SHF_MASKOS)   = 0x0ff00000,
  _LIEF_EI(SHF_MASKPROC) = 0xf0000000, /**< Bits indicating processor-specific flags. */

  /* If an object file section does not have this flag set, then it may not hold
   * more than 2GB and can be freely referred to in objects using smaller code
   * models. Otherwise, only objects using larger code models can refer to them.
   * For example, a medium code model object can refer to data in a section that
   * sets this flag besides being able to refer to data in a section that does
   * not set it; likewise, a small code model object can refer only to code in a
   * section that does not set this flag.
   */
  _LIEF_EI(SHF_X86_64_LARGE) = 0x10000000,

  /* All sections with the GPREL flag are grouped into a global data area
   * for faster accesses.
   */
  _LIEF_EI(SHF_HEX_GPREL) = 0x10000000,

  /* Section contains text/data which may be replicated in other sections.
   * Linker must retain only one copy.
   */
  _LIEF_EI(SHF_MIPS_NODUPES) = 0x01000000,

  _LIEF_EI(SHF_MIPS_NAMES)   = 0x02000000, /**< Linker must generate implicit hidden weak names. */
  _LIEF_EI(SHF_MIPS_LOCAL)   = 0x04000000, /**< Section data local to process. */
  _LIEF_EI(SHF_MIPS_NOSTRIP) = 0x08000000, /**< Do not strip this section. */
  _LIEF_EI(SHF_MIPS_GPREL)   = 0x10000000, /**< Section must be part of global data area. */
  _LIEF_EI(SHF_MIPS_MERGE)   = 0x20000000, /**< This section should be merged. */
  _LIEF_EI(SHF_MIPS_ADDR)    = 0x40000000, /**< Address size to be inferred from section entry size. */
  _LIEF_EI(SHF_MIPS_STRING)  = 0x80000000  /**< Section data is string data by default. */
};


/** Symbol bindings. */
enum _LIEF_EN(SYMBOL_BINDINGS) {
  _LIEF_EI(STB_LOCAL)      = 0,  /**< Local symbol, not visible outside obj file containing def */
  _LIEF_EI(STB_GLOBAL)     = 1,  /**< Global symbol, visible to all object files being combined */
  _LIEF_EI(STB_WEAK)       = 2,  /**< Weak symbol, like global but lower-precedence */
  _LIEF_EI(STB_GNU_UNIQUE) = 10,
  _LIEF_EI(STB_LOOS)       = 10, /**< Lowest operating system-specific binding type */
  _LIEF_EI(STB_HIOS)       = 12, /**< Highest operating system-specific binding type */
  _LIEF_EI(STB_LOPROC)     = 13, /**< Lowest processor-specific binding type */
  _LIEF_EI(STB_HIPROC)     = 15  /**< Highest processor-specific binding type */
};


/* Symbol types. */
enum _LIEF_EN(ELF_SYMBOL_TYPES) {
  _LIEF_EI(STT_NOTYPE)    = 0,   /* Symbol's type is not specified */
  _LIEF_EI(STT_OBJECT)    = 1,   /* Symbol is a data object (variable, array, etc.) */
  _LIEF_EI(STT_FUNC)      = 2,   /* Symbol is executable code (function, etc.) */
  _LIEF_EI(STT_SECTION)   = 3,   /* Symbol refers to a section */
  _LIEF_EI(STT_FILE)      = 4,   /* Local, absolute symbol that refers to a file */
  _LIEF_EI(STT_COMMON)    = 5,   /* An uninitialized common block */
  _LIEF_EI(STT_TLS)       = 6,   /* Thread local data object */
  _LIEF_EI(STT_GNU_IFUNC) = 10,  /* GNU indirect function */
  _LIEF_EI(STT_LOOS)      = 10,  /* Lowest operating system-specific symbol type */
  _LIEF_EI(STT_HIOS)      = 12,  /* Highest operating system-specific symbol type */
  _LIEF_EI(STT_LOPROC)    = 13,  /* Lowest processor-specific symbol type */
  _LIEF_EI(STT_HIPROC)    = 15   /* Highest processor-specific symbol type */
};

enum _LIEF_EN(ELF_SYMBOL_VISIBILITY) {
  _LIEF_EI(STV_DEFAULT)   = 0,  /* Visibility is specified by binding type */
  _LIEF_EI(STV_INTERNAL)  = 1,  /* Defined by processor supplements */
  _LIEF_EI(STV_HIDDEN)    = 2,  /* Not visible to other components */
  _LIEF_EI(STV_PROTECTED) = 3   /* Visible in other components but not preemptable */
};


/** @brief Segment types. */
enum _LIEF_EN(SEGMENT_TYPES) {
  _LIEF_EI(PT_NULL)          = 0,          /**< Unused segment. */
  _LIEF_EI(PT_LOAD)          = 1,          /**< Loadable segment. */
  _LIEF_EI(PT_DYNAMIC)       = 2,          /**< Dynamic linking information. */
  _LIEF_EI(PT_INTERP)        = 3,          /**< Interpreter pathname. */
  _LIEF_EI(PT_NOTE)          = 4,          /**< Auxiliary information. */
  _LIEF_EI(PT_SHLIB)         = 5,          /**< Reserved. */
  _LIEF_EI(PT_PHDR)          = 6,          /**< The program header table itself. */
  _LIEF_EI(PT_TLS)           = 7,          /**< The thread-local storage template. */
  _LIEF_EI(PT_LOOS)          = 0x60000000, /**< Lowest operating system-specific pt entry type. */
  _LIEF_EI(PT_HIOS)          = 0x6fffffff, /**< Highest operating system-specific pt entry type. */
  _LIEF_EI(PT_LOPROC)        = 0x70000000, /**< Lowest processor-specific program hdr entry type. */
  _LIEF_EI(PT_HIPROC)        = 0x7fffffff, /**< Highest processor-specific program hdr entry type. */

  /* x86-64 program header types. */
  /* These all contain stack unwind tables. */
  _LIEF_EI(PT_GNU_EH_FRAME)  = 0x6474e550,
  _LIEF_EI(PT_SUNW_EH_FRAME) = 0x6474e550,
  _LIEF_EI(PT_SUNW_UNWIND)   = 0x6464e550,

  _LIEF_EI(PT_GNU_STACK)     = 0x6474e551, /**< Indicates stack executability. */
  _LIEF_EI(PT_GNU_PROPERTY)  = 0x6474e553, /**< GNU property */
  _LIEF_EI(PT_GNU_RELRO)     = 0x6474e552, /**< Read-only after relocation. */

  /* ARM program header types. */
  _LIEF_EI(PT_ARM_ARCHEXT)   = 0x70000000, /**< Platform architecture compatibility info */

  /* These all contain stack unwind tables. */
  _LIEF_EI(PT_ARM_EXIDX)     = 0x70000001,
  _LIEF_EI(PT_ARM_UNWIND)    = 0x70000001,

  /* MIPS program header types. */
  _LIEF_EI(PT_MIPS_REGINFO)  = 0x70000000,  /**< Register usage information. */
  _LIEF_EI(PT_MIPS_RTPROC)   = 0x70000001,  /**< Runtime procedure table. */
  _LIEF_EI(PT_MIPS_OPTIONS)  = 0x70000002,  /**< Options segment. */
  _LIEF_EI(PT_MIPS_ABIFLAGS) = 0x70000003   /**< Abiflags segment. */
};


/** Segment flags. */
enum _LIEF_EN(ELF_SEGMENT_FLAGS) {
   _LIEF_EI(PF_NONE)     = 0,
   _LIEF_EI(PF_X)        = 1,         /**< Execute */
   _LIEF_EI(PF_W)        = 2,         /**< Write */
   _LIEF_EI(PF_R)        = 4,         /**< Read */
   _LIEF_EI(PF_MASKOS)   = 0x0ff00000,/**< Bits for operating system-specific semantics. */
   _LIEF_EI(PF_MASKPROC) = 0xf0000000 /**< Bits for processor-specific semantics. */
};


/** Dynamic table entry tags. */
enum _LIEF_EN(DYNAMIC_TAGS) {
  _LIEF_EI(DT_NULL)                       = 0,          /**< Marks end of dynamic array. */
  _LIEF_EI(DT_NEEDED)                     = 1,          /**< String table offset of needed library. */
  _LIEF_EI(DT_PLTRELSZ)                   = 2,          /**< Size of relocation entries in PLT. */
  _LIEF_EI(DT_PLTGOT)                     = 3,          /**< Address associated with linkage table. */
  _LIEF_EI(DT_HASH)                       = 4,          /**< Address of symbolic hash table. */
  _LIEF_EI(DT_STRTAB)                     = 5,          /**< Address of dynamic string table. */
  _LIEF_EI(DT_SYMTAB)                     = 6,          /**< Address of dynamic symbol table. */
  _LIEF_EI(DT_RELA)                       = 7,          /**< Address of relocation table (Rela entries). */
  _LIEF_EI(DT_RELASZ)                     = 8,          /**< Size of Rela relocation table. */
  _LIEF_EI(DT_RELAENT)                    = 9,          /**< Size of a Rela relocation entry. */
  _LIEF_EI(DT_STRSZ)                      = 10,         /**< Total size of the string table. */
  _LIEF_EI(DT_SYMENT)                     = 11,         /**< Size of a symbol table entry. */
  _LIEF_EI(DT_INIT)                       = 12,         /**< Address of initialization function. */
  _LIEF_EI(DT_FINI)                       = 13,         /**< Address of termination function. */
  _LIEF_EI(DT_SONAME)                     = 14,         /**< String table offset of a shared objects name. */
  _LIEF_EI(DT_RPATH)                      = 15,         /**< String table offset of library search path. */
  _LIEF_EI(DT_SYMBOLIC)                   = 16,         /**< Changes symbol resolution algorithm. */
  _LIEF_EI(DT_REL)                        = 17,         /**< Address of relocation table (Rel entries). */
  _LIEF_EI(DT_RELSZ)                      = 18,         /**< Size of Rel relocation table. */
  _LIEF_EI(DT_RELENT)                     = 19,         /**< Size of a Rel relocation entry. */
  _LIEF_EI(DT_PLTREL)                     = 20,         /**< Type of relocation entry used for linking. */
  _LIEF_EI(DT_DEBUG)                      = 21,         /**< Reserved for debugger. */
  _LIEF_EI(DT_TEXTREL)                    = 22,         /**< Relocations exist for non-writable segments. */
  _LIEF_EI(DT_JMPREL)                     = 23,         /**< Address of relocations associated with PLT. */
  _LIEF_EI(DT_BIND_NOW)                   = 24,         /**< Process all relocations before execution. */
  _LIEF_EI(DT_INIT_ARRAY)                 = 25,         /**< Pointer to array of initialization functions. */
  _LIEF_EI(DT_FINI_ARRAY)                 = 26,         /**< Pointer to array of termination functions. */
  _LIEF_EI(DT_INIT_ARRAYSZ)               = 27,         /**< Size of DT_INIT_ARRAY. */
  _LIEF_EI(DT_FINI_ARRAYSZ)               = 28,         /**< Size of DT_FINI_ARRAY. */
  _LIEF_EI(DT_RUNPATH)                    = 29,         /**< String table offset of lib search path. */
  _LIEF_EI(DT_FLAGS)                      = 30,         /**< Flags. */
  _LIEF_EI(DT_ENCODING)                   = 32,         /**< Values from here to DT_LOOS follow the rules for the interpretation of the d_un union. */

  _LIEF_EI(DT_PREINIT_ARRAY)              = 32,         /**< Pointer to array of preinit functions. */
  _LIEF_EI(DT_PREINIT_ARRAYSZ)            = 33,         /**< Size of the DT_PREINIT_ARRAY array. */

  _LIEF_EI(DT_LOOS)                       = 0x60000000, /**< Start of environment specific tags. */
  _LIEF_EI(DT_HIOS)                       = 0x6FFFFFFF, /**< End of environment specific tags. */
  _LIEF_EI(DT_LOPROC)                     = 0x70000000, /**< Start of processor specific tags. */
  _LIEF_EI(DT_HIPROC)                     = 0x7FFFFFFF, /**< End of processor specific tags. */

  _LIEF_EI(DT_GNU_HASH)                   = 0x6FFFFEF5, /**< Reference to the GNU hash table. */
  _LIEF_EI(DT_RELACOUNT)                  = 0x6FFFFFF9, /**< ELF32_Rela count. */
  _LIEF_EI(DT_RELCOUNT)                   = 0x6FFFFFFA, /**< ELF32_Rel count. */

  _LIEF_EI(DT_FLAGS_1)                    = 0x6FFFFFFB, /**< Flags_1. */
  _LIEF_EI(DT_VERSYM)                     = 0x6FFFFFF0, /**< The address of .gnu.version section. */
  _LIEF_EI(DT_VERDEF)                     = 0x6FFFFFFC, /**< The address of the version definition table. */
  _LIEF_EI(DT_VERDEFNUM)                  = 0x6FFFFFFD, /**< The number of entries in DT_VERDEF. */
  _LIEF_EI(DT_VERNEED)                    = 0x6FFFFFFE, /**< The address of the version Dependency table. */
  _LIEF_EI(DT_VERNEEDNUM)                 = 0x6FFFFFFF, /**< The number of entries in DT_VERNEED. */

  /* Mips specific dynamic table entry tags. */
  _LIEF_EI(DT_MIPS_RLD_VERSION)           = 0x70000001, /**< 32 bit version number for runtime linker interface. */
  _LIEF_EI(DT_MIPS_TIME_STAMP)            = 0x70000002, /**< Time stamp. */
  _LIEF_EI(DT_MIPS_ICHECKSUM)             = 0x70000003, /**< Checksum of external strings and common sizes. */
  _LIEF_EI(DT_MIPS_IVERSION)              = 0x70000004, /**< Index of version string in string table. */
  _LIEF_EI(DT_MIPS_FLAGS)                 = 0x70000005, /**< 32 bits of flags. */
  _LIEF_EI(DT_MIPS_BASE_ADDRESS)          = 0x70000006, /**< Base address of the segment. */
  _LIEF_EI(DT_MIPS_MSYM)                  = 0x70000007, /**< Address of .msym section. */
  _LIEF_EI(DT_MIPS_CONFLICT)              = 0x70000008, /**< Address of .conflict section. */
  _LIEF_EI(DT_MIPS_LIBLIST)               = 0x70000009, /**< Address of .liblist section. */
  _LIEF_EI(DT_MIPS_LOCAL_GOTNO)           = 0x7000000a, /**< Number of local global offset table entries. */
  _LIEF_EI(DT_MIPS_CONFLICTNO)            = 0x7000000b, /**< Number of entries in the .conflict section. */
  _LIEF_EI(DT_MIPS_LIBLISTNO)             = 0x70000010, /**< Number of entries in the .liblist section. */
  _LIEF_EI(DT_MIPS_SYMTABNO)              = 0x70000011, /**< Number of entries in the .dynsym section. */
  _LIEF_EI(DT_MIPS_UNREFEXTNO)            = 0x70000012, /**< Index of first external dynamic symbol not referenced locally. */
  _LIEF_EI(DT_MIPS_GOTSYM)                = 0x70000013, /**< Index of first dynamic symbol in global offset table. */
  _LIEF_EI(DT_MIPS_HIPAGENO)              = 0x70000014, /**< Number of page table entries in global offset table. */
  _LIEF_EI(DT_MIPS_RLD_MAP)               = 0x70000016, /**< Address of run time loader map, used for debugging. */
  _LIEF_EI(DT_MIPS_DELTA_CLASS)           = 0x70000017, /**< Delta C++ class definition. */
  _LIEF_EI(DT_MIPS_DELTA_CLASS_NO)        = 0x70000018, /**< Number of entries in DT_MIPS_DELTA_CLASS. */
  _LIEF_EI(DT_MIPS_DELTA_INSTANCE)        = 0x70000019, /**< Delta C++ class instances. */
  _LIEF_EI(DT_MIPS_DELTA_INSTANCE_NO)     = 0x7000001A, /**< Number of entries in DT_MIPS_DELTA_INSTANCE. */
  _LIEF_EI(DT_MIPS_DELTA_RELOC)           = 0x7000001B, /**< Delta relocations. */
  _LIEF_EI(DT_MIPS_DELTA_RELOC_NO)        = 0x7000001C, /**< Number of entries in DT_MIPS_DELTA_RELOC. */
  _LIEF_EI(DT_MIPS_DELTA_SYM)             = 0x7000001D, /**< Delta symbols that Delta relocations refer to. */
  _LIEF_EI(DT_MIPS_DELTA_SYM_NO)          = 0x7000001E, /**< Number of entries in DT_MIPS_DELTA_SYM. */
  _LIEF_EI(DT_MIPS_DELTA_CLASSSYM)        = 0x70000020, /**< Delta symbols that hold class declarations. */
  _LIEF_EI(DT_MIPS_DELTA_CLASSSYM_NO)     = 0x70000021, /**< Number of entries in DT_MIPS_DELTA_CLASSSYM. */
  _LIEF_EI(DT_MIPS_CXX_FLAGS)             = 0x70000022, /**< Flags indicating information about C++ flavor. */
  _LIEF_EI(DT_MIPS_PIXIE_INIT)            = 0x70000023, /**< Pixie information. */
  _LIEF_EI(DT_MIPS_SYMBOL_LIB)            = 0x70000024, /**< Address of .MIPS.symlib */
  _LIEF_EI(DT_MIPS_LOCALPAGE_GOTIDX)      = 0x70000025, /**< The GOT index of the first PTE for a segment */
  _LIEF_EI(DT_MIPS_LOCAL_GOTIDX)          = 0x70000026, /**< The GOT index of the first PTE for a local symbol */
  _LIEF_EI(DT_MIPS_HIDDEN_GOTIDX)         = 0x70000027, /**< The GOT index of the first PTE for a hidden symbol */
  _LIEF_EI(DT_MIPS_PROTECTED_GOTIDX)      = 0x70000028, /**< The GOT index of the first PTE for a protected symbol */
  _LIEF_EI(DT_MIPS_OPTIONS)               = 0x70000029, /**< Address of `.MIPS.options'. */
  _LIEF_EI(DT_MIPS_INTERFACE)             = 0x7000002A, /**< Address of `.interface'. */
  _LIEF_EI(DT_MIPS_DYNSTR_ALIGN)          = 0x7000002B, /**< Unknown. */
  _LIEF_EI(DT_MIPS_INTERFACE_SIZE)        = 0x7000002C, /**< Size of the .interface section. */
  _LIEF_EI(DT_MIPS_RLD_TEXT_RESOLVE_ADDR) = 0x7000002D, /**< Size of rld_text_resolve function stored in the GOT. */
  _LIEF_EI(DT_MIPS_PERF_SUFFIX)           = 0x7000002E, /**< Default suffix of DSO to be added by rld on dlopen() calls. */
  _LIEF_EI(DT_MIPS_COMPACT_SIZE)          = 0x7000002F, /**< Size of compact relocation section (O32). */
  _LIEF_EI(DT_MIPS_GP_VALUE)              = 0x70000030, /**< GP value for auxiliary GOTs. */
  _LIEF_EI(DT_MIPS_AUX_DYNAMIC)           = 0x70000031, /**< Address of auxiliary .dynamic. */
  _LIEF_EI(DT_MIPS_PLTGOT)                = 0x70000032, /**< Address of the base of the PLTGOT. */
  _LIEF_EI(DT_MIPS_RWPLT)                 = 0x70000034, /**< Points to the base of a writable PLT. */

  /* Android specific dynamic table entry tags. */
  _LIEF_EI(DT_ANDROID_REL_OFFSET)         = 0x6000000D, /**< The offset of packed relocation data (older version < M) (Android specific). */
  _LIEF_EI(DT_ANDROID_REL_SIZE)           = 0x6000000E, /**< The size of packed relocation data in bytes (older version < M) (Android specific). */
  _LIEF_EI(DT_ANDROID_REL)                = 0x6000000F, /**< The offset of packed relocation data (Android specific). */
  _LIEF_EI(DT_ANDROID_RELSZ)              = 0x60000010, /**< The size of packed relocation data in bytes (Android specific). */
  _LIEF_EI(DT_ANDROID_RELA)               = 0x60000011, /**< The offset of packed relocation data (Android specific). */
  _LIEF_EI(DT_ANDROID_RELASZ)             = 0x60000012, /**< The size of packed relocation data in bytes (Android specific). */
  _LIEF_EI(DT_RELR)                       = 0x6FFFE000, /**< The offset of new relr relocation data (Android specific). */
  _LIEF_EI(DT_RELRSZ)                     = 0x6FFFE001, /**< The size of nre relr relocation data in bytes (Android specific). */
  _LIEF_EI(DT_RELRENT)                    = 0x6FFFE003, /**< The size of a new relr relocation entry (Android specific). */
  _LIEF_EI(DT_RELRCOUNT)                  = 0x6FFFE005 /**< Specifies the relative count of new relr relocation entries (Android specific). */
};

/** DT_FLAGS and DT_FLAGS_1 values. */
enum _LIEF_EN(DYNAMIC_FLAGS) {
  _LIEF_EI(DF_ORIGIN)       = 0x00000001, /**< The object may reference $ORIGIN. */
  _LIEF_EI(DF_SYMBOLIC)     = 0x00000002, /**< Search the shared lib before searching the exe. */
  _LIEF_EI(DF_TEXTREL)      = 0x00000004, /**< Relocations may modify a non-writable segment. */
  _LIEF_EI(DF_BIND_NOW)     = 0x00000008, /**< Process all relocations on load. */
  _LIEF_EI(DF_STATIC_TLS)   = 0x00000010, /**< Reject attempts to load dynamically. */
};

enum _LIEF_EN(DYNAMIC_FLAGS_1) {
  _LIEF_EI(DF_1_NOW)        = 0x00000001, /**< Set RTLD_NOW for this object. */
  _LIEF_EI(DF_1_GLOBAL)     = 0x00000002, /**< Set RTLD_GLOBAL for this object. */
  _LIEF_EI(DF_1_GROUP)      = 0x00000004, /**< Set RTLD_GROUP for this object. */
  _LIEF_EI(DF_1_NODELETE)   = 0x00000008, /**< Set RTLD_NODELETE for this object. */
  _LIEF_EI(DF_1_LOADFLTR)   = 0x00000010, /**< Trigger filtee loading at runtime. */
  _LIEF_EI(DF_1_INITFIRST)  = 0x00000020, /**< Set RTLD_INITFIRST for this object. */
  _LIEF_EI(DF_1_NOOPEN)     = 0x00000040, /**< Set RTLD_NOOPEN for this object. */
  _LIEF_EI(DF_1_ORIGIN)     = 0x00000080, /**< $ORIGIN must be handled. */
  _LIEF_EI(DF_1_DIRECT)     = 0x00000100, /**< Direct binding enabled. */
  _LIEF_EI(DF_1_TRANS)      = 0x00000200,
  _LIEF_EI(DF_1_INTERPOSE)  = 0x00000400, /**< Object is used to interpose. */
  _LIEF_EI(DF_1_NODEFLIB)   = 0x00000800, /**< Ignore default lib search path. */
  _LIEF_EI(DF_1_NODUMP)     = 0x00001000, /**< Object can't be dldump'ed. */
  _LIEF_EI(DF_1_CONFALT)    = 0x00002000, /**< Configuration alternative created. */
  _LIEF_EI(DF_1_ENDFILTEE)  = 0x00004000, /**< Filtee terminates filters search. */
  _LIEF_EI(DF_1_DISPRELDNE) = 0x00008000, /**< Disp reloc applied at build time. */
  _LIEF_EI(DF_1_DISPRELPND) = 0x00010000, /**< Disp reloc applied at run-time. */
  _LIEF_EI(DF_1_NODIRECT)   = 0x00020000, /**< Object has no-direct binding. */
  _LIEF_EI(DF_1_IGNMULDEF)  = 0x00040000,
  _LIEF_EI(DF_1_NOKSYMS)    = 0x00080000,
  _LIEF_EI(DF_1_NOHDR)      = 0x00100000,
  _LIEF_EI(DF_1_EDITED)     = 0x00200000, /**< Object is modified after built. */
  _LIEF_EI(DF_1_NORELOC)    = 0x00400000,
  _LIEF_EI(DF_1_SYMINTPOSE) = 0x00800000, /**< Object has individual interposers. */
  _LIEF_EI(DF_1_GLOBAUDIT)  = 0x01000000, /**< Global auditing required. */
  _LIEF_EI(DF_1_SINGLETON)  = 0x02000000,  /**< Singleton symbols are used. */
  _LIEF_EI(DF_1_PIE)        = 0x08000000  /**< Singleton symbols are used. */
};

/* DT_MIPS_FLAGS values. */
enum {
  _LIEF_EI(RHF_NONE)                    = 0x00000000, /* No flags. */
  _LIEF_EI(RHF_QUICKSTART)              = 0x00000001, /* Uses shortcut pointers. */
  _LIEF_EI(RHF_NOTPOT)                  = 0x00000002, /* Hash size is not a power of two. */
  _LIEF_EI(RHS_NO_LIBRARY_REPLACEMENT)  = 0x00000004, /* Ignore LD_LIBRARY_PATH. */
  _LIEF_EI(RHF_NO_MOVE)                 = 0x00000008, /* DSO address may not be relocated. */
  _LIEF_EI(RHF_SGI_ONLY)                = 0x00000010, /* SGI specific features. */
  _LIEF_EI(RHF_GUARANTEE_INIT)          = 0x00000020, /* Guarantee that .init will finish */
  /* executing before any non-init */
  /* code in DSO is called. */
  _LIEF_EI(RHF_DELTA_C_PLUS_PLUS)       = 0x00000040, /* Contains Delta C++ code. */
  _LIEF_EI(RHF_GUARANTEE_START_INIT)    = 0x00000080, /* Guarantee that .init will start */
  /* executing before any non-init */
  /* code in DSO is called. */
  _LIEF_EI(RHF_PIXIE)                   = 0x00000100, /* Generated by pixie. */
  _LIEF_EI(RHF_DEFAULT_DELAY_LOAD)      = 0x00000200, /* Delay-load DSO by default. */
  _LIEF_EI(RHF_REQUICKSTART)            = 0x00000400, /* Object may be requickstarted */
  _LIEF_EI(RHF_REQUICKSTARTED)          = 0x00000800, /* Object has been requickstarted */
  _LIEF_EI(RHF_CORD)                    = 0x00001000, /* Generated by cord. */
  _LIEF_EI(RHF_NO_UNRES_UNDEF)          = 0x00002000, /* Object contains no unresolved */
  /* undef symbols. */
  _LIEF_EI(RHF_RLD_ORDER_SAFE)          = 0x00004000  /* Symbol table is in a safe order. */
};

/** ElfXX_VerDef structure version (GNU versioning) */
enum {
  _LIEF_EI(VER_DEF_NONE)    = 0,
  _LIEF_EI(VER_DEF_CURRENT) = 1
};

/** VerDef Flags (ElfXX_VerDef::vd_flags) */
enum {
  _LIEF_EI(VER_FLG_BASE) = 0x1,
  _LIEF_EI(VER_FLG_WEAK) = 0x2,
  _LIEF_EI(VER_FLG_INFO) = 0x4
};

/** Special constants for the version table. (SHT_GNU_versym/.gnu.version) */
enum {
  _LIEF_EI(VER_NDX_LOCAL)  = 0,      /**< Unversioned local symbol */
  _LIEF_EI(VER_NDX_GLOBAL) = 1,      /**< Unversioned global symbol */
  _LIEF_EI(VERSYM_VERSION) = 0x7fff, /**< Version Index mask */
  _LIEF_EI(VERSYM_HIDDEN)  = 0x8000  /**< Hidden bit (non-default version) */
};

/** ElfXX_VerNeed structure version (GNU versioning) */
enum {
  _LIEF_EI(VER_NEED_NONE) = 0,
  _LIEF_EI(VER_NEED_CURRENT) = 1
};


enum _LIEF_EN(AUX_TYPE) {

   _LIEF_EI(AT_NULL)          = 0,     /**< End of vector */
   _LIEF_EI(AT_IGNORE)        = 1,     /**< Entry should be ignored */
   _LIEF_EI(AT_EXECFD)        = 2,     /**< File descriptor of program */
   _LIEF_EI(AT_PHDR)          = 3,     /**< Program headers for program */
   _LIEF_EI(AT_PHENT)         = 4,     /**< Size of program header entry */
   _LIEF_EI(AT_PHNUM)         = 5,     /**< Number of program headers */
   _LIEF_EI(AT_PAGESZ)        = 6,     /**< System page size */
   _LIEF_EI(AT_BASE)          = 7,     /**< Base address of interpreter */
   _LIEF_EI(AT_FLAGS)         = 8,     /**< Flags */
   _LIEF_EI(AT_ENTRY)         = 9,     /**< Entry point of program */
   _LIEF_EI(AT_NOTELF)        = 10,    /**< Program is not ELF */
   _LIEF_EI(AT_UID)           = 11,    /**< Real uid */
   _LIEF_EI(AT_EUID)          = 12,    /**< Effective uid */
   _LIEF_EI(AT_GID)           = 13,    /**< Real gid */
   _LIEF_EI(AT_EGID)          = 14,    /**< Effective gid */
   _LIEF_EI(AT_CLKTCK)        = 17,    /**< Frequency of times() */

   /* Some more special a_type values describing the hardware.  */

   _LIEF_EI(AT_PLATFORM)      = 15,    /**< String identifying platform.  */
   _LIEF_EI(AT_HWCAP)         = 16,    /**< Machine dependent hints about processor capabilities.  */

   /* This entry gives some information about the FPU initialization
      performed by the kernel. */

   _LIEF_EI(AT_FPUCW)        = 18,    /**< Used FPU control word.  */

   /* Cache block sizes. */
   _LIEF_EI(AT_DCACHEBSIZE)   = 19,    /**< Data cache block size.  */
   _LIEF_EI(AT_ICACHEBSIZE)   = 20,    /**< Instruction cache block size.  */
   _LIEF_EI(AT_UCACHEBSIZE)   = 21,    /**< Unified cache block size.  */

   /* A special ignored value for PPC, used by the kernel to control the
      interpretation of the AUXV. Must be > 16.  */

   _LIEF_EI(AT_IGNOREPPC)     = 22,    /**< Entry should be ignored.  */
   _LIEF_EI(AT_SECURE)        = 23,    /**< Boolean, was exec setuid-like?  */
   _LIEF_EI(AT_BASE_PLATFORM) = 24,    /**< String identifying real platforms.*/
   _LIEF_EI(AT_RANDOM)        = 25,    /**< Address of 16 random bytes.  */
   _LIEF_EI(AT_HWCAP2)        = 26,    /**< Extension of AT_HWCAP.  */
   _LIEF_EI(AT_EXECFN)        = 31,    /**< Filename of executable.  */

   /* Pointer to the global system page used for system calls and other
      nice things. */
   _LIEF_EI(AT_SYSINFO)       = 32,
   _LIEF_EI(AT_SYSINFO_EHDR)  = 33,

   /* Shapes of the caches.  Bits 0-3 contains associativity; bits 4-7 contains
      log2 of line size; mask those to get cache size.  */
   _LIEF_EI(AT_L1I_CACHESHAPE)  = 34,
   _LIEF_EI(AT_L1D_CACHESHAPE)  = 35,
   _LIEF_EI(AT_L2_CACHESHAPE)   = 36,
   _LIEF_EI(AT_L3_CACHESHAPE)   = 37
};

/** Methods that can be used by the LIEF::ELF::Parser
    to count the number of dynamic symbols */
enum _LIEF_EN(DYNSYM_COUNT_METHODS) {
  _LIEF_EI(COUNT_AUTO)        = 0, /**< Automatic detection */
  _LIEF_EI(COUNT_SECTION)     = 1, /**< Count based on sections (not very reliable) */
  _LIEF_EI(COUNT_HASH)        = 2, /**< Count based on hash table (reliable) */
  _LIEF_EI(COUNT_RELOCATIONS) = 3, /**< Count based on PLT/GOT relocations (very reliable but not accurate) */
};

enum _LIEF_EN(NOTE_TYPES) {
  _LIEF_EI(NT_UNKNOWN)          = 0,
  _LIEF_EI(NT_GNU_ABI_TAG)      = 1,
  _LIEF_EI(NT_GNU_HWCAP)        = 2,
  _LIEF_EI(NT_GNU_BUILD_ID)     = 3,
  _LIEF_EI(NT_GNU_GOLD_VERSION) = 4,
  _LIEF_EI(NT_CRASHPAD)         = 0x4f464e49,
};

enum _LIEF_EN(NOTE_TYPES_CORE) {
  _LIEF_EI(NT_CORE_UNKNOWN)     = 0,
  _LIEF_EI(NT_PRSTATUS)         = 1,
  _LIEF_EI(NT_PRFPREG)          = 2,
  _LIEF_EI(NT_PRPSINFO)         = 3,
  _LIEF_EI(NT_TASKSTRUCT)       = 4,
  _LIEF_EI(NT_AUXV)             = 6,
  _LIEF_EI(NT_SIGINFO)          = 0x53494749,
  _LIEF_EI(NT_FILE)             = 0x46494c45,
  _LIEF_EI(NT_PRXFPREG)         = 0x46e62b7f,

  _LIEF_EI(NT_ARM_VFP)          = 0x400,
  _LIEF_EI(NT_ARM_TLS)          = 0x401,
  _LIEF_EI(NT_ARM_HW_BREAK)     = 0x402,
  _LIEF_EI(NT_ARM_HW_WATCH)     = 0x403,
  _LIEF_EI(NT_ARM_SYSTEM_CALL)  = 0x404,
  _LIEF_EI(NT_ARM_SVE)          = 0x405,

  _LIEF_EI(NT_386_TLS)          = 0x200,
  _LIEF_EI(NT_386_IOPERM)       = 0x201,
  _LIEF_EI(NT_386_XSTATE)       = 0x202,

};


enum _LIEF_EN(NOTE_ABIS) {
  _LIEF_EI(ELF_NOTE_UNKNOWN)     = ~(unsigned int)(0),
  _LIEF_EI(ELF_NOTE_OS_LINUX)    = 0,
  _LIEF_EI(ELF_NOTE_OS_GNU)      = 1,
  _LIEF_EI(ELF_NOTE_OS_SOLARIS2) = 2,
  _LIEF_EI(ELF_NOTE_OS_FREEBSD)  = 3,
  _LIEF_EI(ELF_NOTE_OS_NETBSD)   = 4,
  _LIEF_EI(ELF_NOTE_OS_SYLLABLE) = 5,
};

enum _LIEF_EN(RELOCATION_PURPOSES) {
  _LIEF_EI(RELOC_PURPOSE_NONE)    = 0,
  _LIEF_EI(RELOC_PURPOSE_PLTGOT)  = 1,
  _LIEF_EI(RELOC_PURPOSE_DYNAMIC) = 2,
  _LIEF_EI(RELOC_PURPOSE_OBJECT)  = 3,
};



}
}

ENABLE_BITMASK_OPERATORS(LIEF::ELF::ELF_SEGMENT_FLAGS)
ENABLE_BITMASK_OPERATORS(LIEF::ELF::ARM_EFLAGS)
ENABLE_BITMASK_OPERATORS(LIEF::ELF::MIPS_EFLAGS)
ENABLE_BITMASK_OPERATORS(LIEF::ELF::HEXAGON_EFLAGS)
ENABLE_BITMASK_OPERATORS(LIEF::ELF::ELF_SECTION_FLAGS)
ENABLE_BITMASK_OPERATORS(LIEF::ELF::DYNAMIC_FLAGS)
ENABLE_BITMASK_OPERATORS(LIEF::ELF::DYNAMIC_FLAGS_1)

#endif
