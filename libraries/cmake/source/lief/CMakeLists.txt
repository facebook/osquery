# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(lief)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_lief
    "${library_root}/src/Object.cpp"
    "${library_root}/src/Visitor.cpp"
    "${library_root}/src/errors.cpp"
    "${library_root}/src/exception.cpp"
    "${library_root}/src/hash_stream.cpp"
    "${library_root}/src/utils.cpp"
    "${library_root}/src/Object.tcc"
    "${library_root}/src/iostream.cpp"
    "${library_root}/src/logging.cpp"
    "${library_root}/src/Abstract/Binary.cpp"
    "${library_root}/src/Abstract/EnumToString.cpp"
    "${library_root}/src/Abstract/Function.cpp"
    "${library_root}/src/Abstract/Header.cpp"
    "${library_root}/src/Abstract/Parser.cpp"
    "${library_root}/src/Abstract/Relocation.cpp"
    "${library_root}/src/Abstract/Section.cpp"
    "${library_root}/src/Abstract/Symbol.cpp"
    "${library_root}/src/Abstract/hash.cpp"
    "${library_root}/src/BinaryStream/BinaryStream.cpp"
    "${library_root}/src/BinaryStream/Convert.cpp"
    "${library_root}/src/BinaryStream/MemoryStream.cpp"
    "${library_root}/src/BinaryStream/VectorStream.cpp"
    "${library_root}/src/visitors/hash.cpp"
    "${library_root}/src/hash_stream.hpp"
    )

  if(DEFINED PLATFORM_MACOS)
    
    target_sources(thirdparty_lief PRIVATE
      "${library_root}/src/MachO/utils.cpp"
      "${library_root}/src/MachO/Binary.cpp"
      "${library_root}/src/MachO/UUIDCommand.cpp"
      "${library_root}/src/MachO/Symbol.cpp"
      "${library_root}/src/MachO/FatBinary.cpp"
      "${library_root}/src/MachO/EnumToString.cpp"
      "${library_root}/src/MachO/Header.cpp"
      "${library_root}/src/MachO/DynamicSymbolCommand.cpp"
      "${library_root}/src/MachO/Section.cpp"
      "${library_root}/src/MachO/LoadCommand.cpp"
      "${library_root}/src/MachO/BinaryParser.cpp"
      "${library_root}/src/MachO/Builder.cpp"
      "${library_root}/src/MachO/SegmentCommand.cpp"
      "${library_root}/src/MachO/Parser.cpp"
      "${library_root}/src/MachO/SymbolCommand.cpp"
      "${library_root}/src/MachO/MainCommand.cpp"
      "${library_root}/src/MachO/DylibCommand.cpp"
      "${library_root}/src/MachO/DylinkerCommand.cpp"
      "${library_root}/src/MachO/DyldInfo.cpp"
      "${library_root}/src/MachO/Builder.tcc"
      "${library_root}/src/MachO/Binary.tcc"
      "${library_root}/src/MachO/BinaryParser.tcc"
      "${library_root}/src/MachO/FunctionStarts.cpp"
      "${library_root}/src/MachO/SourceVersion.cpp"
      "${library_root}/src/MachO/VersionMin.cpp"
      "${library_root}/src/MachO/Relocation.cpp"
      "${library_root}/src/MachO/RelocationObject.cpp"
      "${library_root}/src/MachO/RelocationDyld.cpp"
      "${library_root}/src/MachO/BindingInfo.cpp"
      "${library_root}/src/MachO/ExportInfo.cpp"
      "${library_root}/src/MachO/ThreadCommand.cpp"
      "${library_root}/src/MachO/RPathCommand.cpp"
      "${library_root}/src/MachO/ParserConfig.cpp"
      "${library_root}/src/MachO/hash.cpp"
      "${library_root}/src/MachO/CodeSignature.cpp"
      "${library_root}/src/MachO/SegmentSplitInfo.cpp"
      "${library_root}/src/MachO/DataInCode.cpp"
      "${library_root}/src/MachO/DataCodeEntry.cpp"
      "${library_root}/src/MachO/SubFramework.cpp"
      "${library_root}/src/MachO/DyldEnvironment.cpp"
      "${library_root}/src/MachO/EncryptionInfo.cpp"
      "${library_root}/src/MachO/TrieNode.cpp"
      "${library_root}/src/MachO/BuildVersion.cpp"
      "${library_root}/src/MachO/TrieNode.hpp"
      )
    target_include_directories(thirdparty_lief PUBLIC
     "${CMAKE_CURRENT_SOURCE_DIR}/generated/macos"
     "${CMAKE_CURRENT_SOURCE_DIR}/config/macos"
     )
  endif()
  if(DEFINED PLATFORM_WINDOWS)
    
    target_sources(thirdparty_lief PRIVATE
      "${library_root}/src/PE/utils.cpp"
      "${library_root}/src/PE/ExportEntry.cpp"
      "${library_root}/src/PE/Binary.cpp"
      "${library_root}/src/PE/Symbol.cpp"
      "${library_root}/src/PE/EnumToString.cpp"
      "${library_root}/src/PE/Header.cpp"
      "${library_root}/src/PE/hash.cpp"
      "${library_root}/src/PE/DosHeader.cpp"
      "${library_root}/src/PE/RichHeader.cpp"
      "${library_root}/src/PE/RichEntry.cpp"
      "${library_root}/src/PE/ResourceDirectory.cpp"
      "${library_root}/src/PE/Import.cpp"
      "${library_root}/src/PE/ResourceNode.cpp"
      "${library_root}/src/PE/Export.cpp"
      "${library_root}/src/PE/Section.cpp"
      "${library_root}/src/PE/OptionalHeader.cpp"
      "${library_root}/src/PE/Builder.cpp"
      "${library_root}/src/PE/Parser.cpp"
      "${library_root}/src/PE/ResourcesManager.cpp"
      "${library_root}/src/PE/Relocation.cpp"
      "${library_root}/src/PE/TLS.cpp"
      "${library_root}/src/PE/Debug.cpp"
      "${library_root}/src/PE/CodeView.cpp"
      "${library_root}/src/PE/CodeViewPDB.cpp"
      "${library_root}/src/PE/Pogo.cpp"
      "${library_root}/src/PE/PogoEntry.cpp"
      "${library_root}/src/PE/ImportEntry.cpp"
      "${library_root}/src/PE/ResourceData.cpp"
      "${library_root}/src/PE/RelocationEntry.cpp"
      "${library_root}/src/PE/DataDirectory.cpp"
      "${library_root}/src/PE/CodeIntegrity.cpp"
      "${library_root}/src/PE/Builder.tcc"
      "${library_root}/src/PE/Parser.tcc"
      "${library_root}/src/PE/resources/ResourceVersion.cpp"
      "${library_root}/src/PE/resources/ResourceDialog.cpp"
      "${library_root}/src/PE/resources/ResourceDialogItem.cpp"
      "${library_root}/src/PE/resources/ResourceVersion.cpp"
      "${library_root}/src/PE/resources/ResourceFixedFileInfo.cpp"
      "${library_root}/src/PE/resources/ResourceVarFileInfo.cpp"
      "${library_root}/src/PE/resources/ResourceStringFileInfo.cpp"
      "${library_root}/src/PE/resources/LangCodeItem.cpp"
      "${library_root}/src/PE/resources/ResourceIcon.cpp"
      "${library_root}/src/PE/resources/ResourceStringTable.cpp"
      "${library_root}/src/PE/resources/ResourceAccelerator.cpp"
      "${library_root}/src/PE/LoadConfigurations/LoadConfigurations.tcc"
      "${library_root}/src/PE/LoadConfigurations/LoadConfiguration.cpp"
      "${library_root}/src/PE/LoadConfigurations/LoadConfiguration.tcc"
      "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV0.cpp"
      "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV0.tcc"
      "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV1.cpp"
      "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV1.tcc"
      "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV2.cpp"
      "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV2.tcc"
      "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV3.cpp"
      "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV3.tcc"
      "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV4.cpp"
      "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV4.tcc"
      "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV5.cpp"
      "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV5.tcc"
      "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV6.cpp"
      "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV6.tcc"
      "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV7.cpp"
      "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV7.tcc"
      "${library_root}/src/PE/signature/Attribute.cpp"
      "${library_root}/src/PE/signature/ContentInfo.cpp"
      "${library_root}/src/PE/signature/Signature.cpp"
      "${library_root}/src/PE/signature/SignerInfo.cpp"
      "${library_root}/src/PE/signature/x509.cpp"
      "${library_root}/src/PE/signature/OIDToString.cpp"
      "${library_root}/src/PE/signature/SignatureParser.cpp"
      "${library_root}/src/PE/signature/RsaInfo.cpp"
      "${library_root}/src/PE/signature/attributes/GenericType.cpp"
      "${library_root}/src/PE/signature/attributes/ContentType.cpp"
      "${library_root}/src/PE/signature/attributes/SpcSpOpusInfo.cpp"
      "${library_root}/src/PE/signature/attributes/MsCounterSign.cpp"
      "${library_root}/src/PE/signature/attributes/MsSpcNestedSignature.cpp"
      "${library_root}/src/PE/signature/attributes/MsSpcStatementType.cpp"
      "${library_root}/src/PE/signature/attributes/PKCS9AtSequenceNumber.cpp"
      "${library_root}/src/PE/signature/attributes/PKCS9CounterSignature.cpp"
      "${library_root}/src/PE/signature/attributes/PKCS9MessageDigest.cpp"
      "${library_root}/src/PE/signature/attributes/PKCS9SigningTime.cpp"
      )
    target_include_directories(thirdparty_lief PRIVATE
      "${library_root}/src/PE/utils/ordinals_lookup_tables"
      "${library_root}/src/PE/utils/ordinals_lookup_tables_std"
      "${library_root}/src/PE/signatures"
      )

    target_include_directories(thirdparty_lief PUBLIC
     "${CMAKE_CURRENT_SOURCE_DIR}/generated/windows"
     "${CMAKE_CURRENT_SOURCE_DIR}/config/windows"
    )
  
    target_compile_definitions(thirdparty_lief PRIVATE NOMINMAX)
    # Used for the 'and', 'or' ... keywords - See: http://www.cplusplus.com/reference/ciso646/
    target_compile_options(thirdparty_lief PUBLIC /FIiso646.h)
  endif()

  if(DEFINED PLATFORM_LINUX)
    
    target_sources(thirdparty_lief PRIVATE
      "${library_root}/src/ELF/Convert.cpp"
      "${library_root}/src/ELF/DynamicEntryArray.cpp"
      "${library_root}/src/ELF/utils.cpp"
      "${library_root}/src/ELF/SymbolVersionRequirement.cpp"
      "${library_root}/src/ELF/SymbolVersionAuxRequirement.cpp"
      "${library_root}/src/ELF/Binary.cpp"
      "${library_root}/src/ELF/Symbol.cpp"
      "${library_root}/src/ELF/EnumToString.cpp"
      "${library_root}/src/ELF/Header.cpp"
      "${library_root}/src/ELF/DynamicSharedObject.cpp"
      "${library_root}/src/ELF/Segment.cpp"
      "${library_root}/src/ELF/Section.cpp"
      "${library_root}/src/ELF/SymbolVersionAux.cpp"
      "${library_root}/src/ELF/GnuHash.cpp"
      "${library_root}/src/ELF/SysvHash.cpp"
      "${library_root}/src/ELF/SymbolVersion.cpp"
      "${library_root}/src/ELF/Builder.cpp"
      "${library_root}/src/ELF/DynamicEntryLibrary.cpp"
      "${library_root}/src/ELF/DataHandler/Node.cpp"
      "${library_root}/src/ELF/DataHandler/Handler.cpp"
      "${library_root}/src/ELF/Parser.cpp"
      "${library_root}/src/ELF/Relocation.cpp"
      "${library_root}/src/ELF/DynamicEntryRunPath.cpp"
      "${library_root}/src/ELF/SymbolVersionDefinition.cpp"
      "${library_root}/src/ELF/DynamicEntry.cpp"
      "${library_root}/src/ELF/DynamicEntryRpath.cpp"
      "${library_root}/src/ELF/DynamicEntryFlags.cpp"
      "${library_root}/src/ELF/Builder.tcc"
      "${library_root}/src/ELF/Parser.tcc"
      "${library_root}/src/ELF/Binary.tcc"
      "${library_root}/src/ELF/hash.cpp"
      "${library_root}/src/ELF/Note.cpp"
      "${library_root}/src/ELF/NoteDetails.cpp"

      "${library_root}/src/ELF/NoteDetails/AndroidNote.cpp"
      "${library_root}/src/ELF/NoteDetails/NoteAbi.cpp"

      "${library_root}/src/ELF/NoteDetails/core/CorePrPsInfo.cpp"
      "${library_root}/src/ELF/NoteDetails/core/CorePrPsInfo.tcc"
      
      "${library_root}/src/ELF/NoteDetails/core/CoreFile.cpp"
      "${library_root}/src/ELF/NoteDetails/core/CoreFile.tcc"

      "${library_root}/src/ELF/NoteDetails/core/CorePrStatus.cpp"
      "${library_root}/src/ELF/NoteDetails/core/CorePrStatus.tcc"

      "${library_root}/src/ELF/NoteDetails/core/CoreAuxv.cpp"
      "${library_root}/src/ELF/NoteDetails/core/CoreAuxv.tcc"

      "${library_root}/src/ELF/NoteDetails/core/CoreSigInfo.cpp"
      )
    target_include_directories(thirdparty_lief PUBLIC
     "${CMAKE_CURRENT_SOURCE_DIR}/generated/linux"
     "${CMAKE_CURRENT_SOURCE_DIR}/config/linux"
     )
  endif()

  target_include_directories(thirdparty_lief PRIVATE
    "${library_root}/include"
    "${library_root}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/third-party"
    )

   target_include_directories(thirdparty_lief PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/third-party"
    )

  target_include_directories(thirdparty_lief SYSTEM INTERFACE
    "${library_root}/include"
    )

  target_compile_definitions(thirdparty_lief PRIVATE LIEF_STATIC)

  target_link_libraries(thirdparty_lief PRIVATE
    thirdparty_cxx_settings
    thirdparty_mbedtls
    thirdparty_spdlog
    )
 add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/third-party/LIEF/third-party/utfcpp/utf8.h
  COMMAND
    ${CMAKE_COMMAND} -E copy_directory ${PROJECT_SOURCE_DIR}/libraries/cmake/source/utfcpp/src/source
    ${CMAKE_CURRENT_SOURCE_DIR}/third-party/LIEF/third-party/utfcpp
    DEPENDS thirdparty_utfcpp)

  target_sources(thirdparty_lief PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/third-party/LIEF/third-party/utfcpp/utf8.h)

endfunction()

lief()
