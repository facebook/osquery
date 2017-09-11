//**********************************************************************`
//* This is an include file generated by Message Compiler.             *`
//*                                                                    *`
//* Copyright (c) Microsoft Corporation. All Rights Reserved.          *`
//**********************************************************************`
#pragma once
//+
// Provider Facebook Event Count 5
//+
EXTERN_C __declspec(selectany) const GUID OsqueryWindowsEventLogProvider = {0xf7740e18, 0x3259, 0x434f, {0x97, 0x59, 0x97, 0x63, 0x19, 0x96, 0x89, 0x00}};

//
// Channel
//
#define OsqueryWindowsEventLogChannel 0x10

//
// Opcodes
//
#define _opcode_message 0xa

//
// Tasks
//
#define WindowsEventLogMessage 0x1
//
// Keyword
//
#define _keyword_info_message 0x1
#define _keyword_warning_message 0x2
#define _keyword_error_message 0x4
#define _keyword_fatal_message 0x8
#define _keyword_debug_message 0x10

//
// Event Descriptors
//
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR DebugMessage = {0x1, 0x0, 0x10, 0x4, 0xa, 0x1, 0x8000000000000010};
#define DebugMessage_value 0x1
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR InfoMessage = {0x2, 0x0, 0x10, 0x4, 0xa, 0x1, 0x8000000000000001};
#define InfoMessage_value 0x2
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR WarningMessage = {0x3, 0x0, 0x10, 0x4, 0xa, 0x1, 0x8000000000000002};
#define WarningMessage_value 0x3
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR ErrorMessage = {0x4, 0x0, 0x10, 0x4, 0xa, 0x1, 0x8000000000000004};
#define ErrorMessage_value 0x4
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR FatalMessage = {0x5, 0x0, 0x10, 0x4, 0xa, 0x1, 0x8000000000000008};
#define FatalMessage_value 0x5
#define MSG_level_Informational              0x50000004L
#define MSG_osquery_channel_PrimaryWindowsEventLogChannel_message 0x90000001L
#define MSG_osquery_event_1_message          0xB0000001L
#define MSG_osquery_event_2_message          0xB0000002L
#define MSG_osquery_event_3_message          0xB0000003L
#define MSG_osquery_event_4_message          0xB0000004L
#define MSG_osquery_event_5_message          0xB0000005L
