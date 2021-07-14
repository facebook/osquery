/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/filesystem/fileops.h>
#include <osquery/logger/logger.h>
#include <osquery/process/process.h>
#include <osquery/process/windows/process_ops.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>

#include <AclAPI.h>
#include <LM.h>
#include <ShlObj.h>
#include <Shlwapi.h>
#include <io.h>
#include <sddl.h>
#include <strsafe.h>

#include <memory>
#include <regex>
#include <set>
#include <vector>

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

namespace fs = boost::filesystem;
namespace errc = boost::system::errc;

namespace osquery {

uint32_t getUidFromSid(PSID sid);
uint32_t getGidFromSid(PSID sid);

/*
 * Avoid having the same right being used in multiple CHMOD_* macros. Doing so
 * will cause issues when requesting certain permissions in the presence of deny
 * access control entries
 */
#define CHMOD_READ (FILE_READ_DATA | FILE_READ_EA)
#define CHMOD_WRITE                                                            \
  (FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA | FILE_WRITE_EA)
#define CHMOD_EXECUTE FILE_EXECUTE

using AclObject = std::unique_ptr<unsigned char[]>;

class WindowsFindFiles {
 public:
  explicit WindowsFindFiles(const fs::path& path) : path_(path) {
    handle_ = ::FindFirstFileW(path_.make_preferred().wstring().c_str(), &fd_);
  }

  ~WindowsFindFiles() {
    if (handle_ != INVALID_HANDLE_VALUE) {
      ::FindClose(handle_);
      handle_ = INVALID_HANDLE_VALUE;
    }
  }

  std::vector<fs::path> get() {
    std::vector<fs::path> results;

    if (handle_ != INVALID_HANDLE_VALUE) {
      do {
        const std::wstring component = fd_.cFileName;
        if (component != L"." && component != L"..") {
          if (path_.has_parent_path()) {
            results.push_back(path_.parent_path() / component);
          } else {
            results.push_back(fs::path(component));
          }
        }

        ::RtlZeroMemory(&fd_, sizeof(fd_));
      } while (::FindNextFileW(handle_, &fd_));
    }

    return results;
  }

  std::vector<fs::path> getDirectories() {
    std::vector<fs::path> results;
    boost::system::error_code ec;

    for (auto const& result : get()) {
      ec.clear();
      if (fs::is_directory(result, ec) && ec.value() == errc::success) {
        results.push_back(result);
      }
    }
    return results;
  }

 private:
  HANDLE handle_{INVALID_HANDLE_VALUE};
  WIN32_FIND_DATAW fd_{0};

  fs::path path_;
};

Status windowsShortPathToLongPath(const std::string& shortPath,
                                  std::string& rLongPath) {
  WCHAR longPath[MAX_PATH];
  auto ret =
      GetLongPathNameW(stringToWstring(shortPath).c_str(), longPath, MAX_PATH);
  if (ret == 0) {
    return Status(GetLastError(), "Failed to convert short path to long path");
  }
  rLongPath = wstringToString(longPath);
  return Status::success();
}

Status windowsGetVersionInfo(const std::string& path,
                             std::string& product_version,
                             std::string& file_version) {
  DWORD handle = 0;
  std::wstring wpath = stringToWstring(path).c_str();
  auto verSize = GetFileVersionInfoSizeW(wpath.c_str(), &handle);
  auto verInfo = std::make_unique<BYTE[]>(verSize);
  if (verInfo == nullptr) {
    return Status(1, "Failed to malloc for version info");
  }
  auto err = GetFileVersionInfoW(
      stringToWstring(path).c_str(), handle, verSize, verInfo.get());
  if (err == 0) {
    return Status(GetLastError(), "Failed to get file version info");
  }
  VS_FIXEDFILEINFO* pFileInfo = nullptr;
  UINT verInfoSize = 0;
  err = VerQueryValue(
      verInfo.get(), TEXT("\\"), (LPVOID*)&pFileInfo, &verInfoSize);
  if (err == 0) {
    return Status(GetLastError(), "Failed to query version value");
  }
  product_version =
      std::to_string((pFileInfo->dwProductVersionMS >> 16 & 0xffff)) + "." +
      std::to_string((pFileInfo->dwProductVersionMS >> 0 & 0xffff)) + "." +
      std::to_string((pFileInfo->dwProductVersionLS >> 16 & 0xffff)) + "." +
      std::to_string((pFileInfo->dwProductVersionLS >> 0 & 0xffff));
  file_version =
      std::to_string((pFileInfo->dwFileVersionMS >> 16 & 0xffff)) + "." +
      std::to_string((pFileInfo->dwFileVersionMS >> 0 & 0xffff)) + "." +
      std::to_string((pFileInfo->dwFileVersionLS >> 16 & 0xffff)) + "." +
      std::to_string((pFileInfo->dwFileVersionLS >> 0 & 0xffff));
  return Status::success();
}

typedef struct LANGANDCODEPAGE {
  WORD wLanguage;
  WORD wCodePage;
} langandcodepage_t;

// retrieve the list of languages and code pages from version information
// ressource
Status getLanguagesAndCodepages(
    const std::unique_ptr<BYTE[]>& versionInfo,
    std::vector<langandcodepage_t>& langs_and_codepages) {
  langandcodepage_t* lpTranslate = nullptr;
  UINT cbTranslate = 0;

  if (VerQueryValueW(versionInfo.get(),
                     L"\\VarFileInfo\\Translation",
                     (LPVOID*)&lpTranslate,
                     &cbTranslate)) {
    for (size_t i = 0; i < (cbTranslate / sizeof(langandcodepage_t)); ++i)
      langs_and_codepages.push_back(lpTranslate[i]);
    return Status::success();
  }
  return Status(GetLastError(), "Failed to read languages and code pages");
}

void initLanguagesAndCodepagesHeuristic(
    std::vector<langandcodepage_t>& langs_and_codepages) {
  langs_and_codepages.push_back({GetUserDefaultLangID(), 0x04B0});
  langs_and_codepages.push_back({GetUserDefaultLangID(), 0x04E4});
  langs_and_codepages.push_back({0x0409, 0x04B0}); // US English + CP_UNICODE
  langs_and_codepages.push_back({0x0409, 0x04E4}); // US English + CP_USASCII
  langs_and_codepages.push_back(
      {0x0409, 0x0000}); // US English + unknown codepage
}

// retrieve OriginalFilename for language and code page from version information
// ressource
Status getOriginalFilenameForCodepage(
    const std::unique_ptr<BYTE[]>& versionInfo,
    const langandcodepage_t& lang_and_codepage,
    std::string& original_filename) {
  WCHAR string_buf[50] = {'\0'};
  size_t string_buf_size = ARRAYSIZE(string_buf);
  WCHAR* lpBuffer = nullptr;
  UINT dwBytes = 0;

  HRESULT hr = StringCchPrintfW(string_buf,
                                string_buf_size,
                                L"\\StringFileInfo\\%04x%04x\\OriginalFilename",
                                lang_and_codepage.wLanguage,
                                lang_and_codepage.wCodePage);
  if (SUCCEEDED(hr) &&
      VerQueryValueW(
          versionInfo.get(), string_buf, (LPVOID*)&lpBuffer, &dwBytes)) {
    original_filename = wstringToString(lpBuffer);
    return Status::success();
  }
  return Status(GetLastError(),
                "Failed to retrieve OriginalFilename for codepage");
}

// retrieve OriginalFilename from version information ressource
// original_filename is only modified on successful read
Status windowsGetOriginalFilename(const std::string& path,
                                  std::string& original_filename) {
  DWORD handle = 0;
  std::wstring wpath = stringToWstring(path);

  // GetFileVersionInfoSize
  auto verSize =
      GetFileVersionInfoSizeExW(FILE_VER_GET_NEUTRAL, wpath.c_str(), &handle);
  if (verSize == 0) {
    return Status(GetLastError(), "Failed to get file version info size");
  }

  // GetFileVersionInfo
  std::unique_ptr<BYTE[]> verInfo;
  try {
    verInfo = std::make_unique<BYTE[]>(verSize);
  } catch (std::bad_alloc /* e */) { /* empty body */
  }
  if (verInfo == nullptr) {
    return Status(1, "Failed to malloc for version info");
  }
  auto err = GetFileVersionInfoExW(
      FILE_VER_GET_NEUTRAL, wpath.c_str(), 0, verSize, verInfo.get());
  if (err == 0) {
    return Status(GetLastError(), "Failed to get file version info");
  }

  // retrieve the list of languages and code pages
  std::vector<langandcodepage_t> langs_and_codepages;
  auto stat = getLanguagesAndCodepages(verInfo, langs_and_codepages);
  if (!stat.ok()) {
    return stat;
  }

  // retrieve OriginalFilename for each language and code page, stop on first
  // successful read
  stat = Status::failure(
      "Failed to retrieve OriginalFilename from version information ressource");
  for (size_t i = 0; i < langs_and_codepages.size(); ++i) {
    stat = getOriginalFilenameForCodepage(
        verInfo, langs_and_codepages[i], original_filename);
    if (stat.ok()) {
      break;
    }
  }
  /*
   * According to
   * https://referencesource.microsoft.com/#system/services/monitoring/system/diagnosticts/FileVersionInfo.cs,469
   * some dlls might not contain correct codepage information. In this case we
   * will fail during lookup. Explorer will take a few shots in dark by trying
   * following ID:
   *
   * 040904B0 // US English + CP_UNICODE
   * 040904E4 // US English + CP_USASCII
   * 04090000 // US English + unknown codepage
   * Explorer also randomly guesses 041D04B0=Swedish+CP_UNICODE and
   * 040704B0=German+CP_UNICODE sometimes. We will try to simulate similiar
   * behavior here.
   */
  if (!stat.ok()) {
    langs_and_codepages.clear();
    initLanguagesAndCodepagesHeuristic(langs_and_codepages);
    for (size_t i = 0; i < langs_and_codepages.size(); ++i) {
      stat = getOriginalFilenameForCodepage(
          verInfo, langs_and_codepages[i], original_filename);
      if (stat.ok()) {
        break;
      }
    }
  }

  return stat.ok() ? Status::success()
                   : Status::failure(
                         "Failed to retrieve OriginalFilename from "
                         "version information ressource");
}

static bool hasGlobBraces(const std::wstring& glob) {
  int brace_depth = 0;
  bool has_brace = false;

  for (size_t i = 0; i < glob.size(); i++) {
    switch (glob[i]) {
    case '{':
      brace_depth += 1;
      has_brace = true;
      break;
    case '}':
      brace_depth -= 1;
      break;
    default:
      break;
    }
  }
  return (brace_depth == 0 && has_brace);
}

AsyncEvent::AsyncEvent() {
  overlapped_.hEvent = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
}

AsyncEvent::~AsyncEvent() {
  if (overlapped_.hEvent != nullptr) {
    ::CloseHandle(overlapped_.hEvent);
  }
}

// Inspired by glob-to-regexp node package
static std::wstring globToRegex(const std::wstring& glob) {
  bool in_group = false;
  std::wstring regex(L"^");

  for (size_t i = 0; i < glob.size(); i++) {
    char c = glob[i];

    switch (c) {
    case L'?':
      regex += L'.';
      break;
    case L'{':
      in_group = true;
      regex += L'(';
      break;
    case L'}':
      in_group = false;
      regex += L')';
      break;
    case L',':
      regex += L'|';
      break;
    case L'*':
      regex += L".*";
      break;
    case L'\\':
    case L'/':
    case L'$':
    case L'^':
    case L'+':
    case L'.':
    case L'(':
    case L')':
    case L'=':
    case L'!':
    case L'|':
      regex += L'\\';
    default:
      regex += c;
      break;
    }
  }

  return regex + L"$";
}

static DWORD getNewAclSize(PACL dacl,
                           PSID sid,
                           ACL_SIZE_INFORMATION& info,
                           bool needs_allowed,
                           bool needs_denied) {
  // This contains the current buffer size of dacl
  DWORD acl_size = info.AclBytesInUse;

  /*
   * By default, we assume that the ACL as pointed to by the dacl argument does
   * not contain any access control entries (further known as ACE) associated
   * with sid. If we require an access allowed and/or access denied ACE, we will
   * increment acl_size by the size of the new ACE.
   */

  if (needs_allowed) {
    acl_size +=
        sizeof(ACCESS_ALLOWED_ACE) + ::GetLengthSid(sid) - sizeof(DWORD);
  }

  if (needs_denied) {
    acl_size += sizeof(ACCESS_DENIED_ACE) + ::GetLengthSid(sid) - sizeof(DWORD);
  }

  /*
   * Enumerate the current ACL looking for ACEs associated with sid. Since our
   * assumption is that such a sid does not exist, we need to subtract their
   * size from acl_size if found.
   */
  PACE_HEADER entry = nullptr;
  for (DWORD i = 0; i < info.AceCount; i++) {
    if (!::GetAce(dacl, i, (LPVOID*)&entry)) {
      return 0;
    }

    // We don't care about inherited ACEs
    if ((entry->AceFlags & INHERITED_ACE) == INHERITED_ACE) {
      break;
    }

    if (entry->AceType == ACCESS_ALLOWED_ACE_TYPE &&
        EqualSid(sid, &((ACCESS_ALLOWED_ACE*)entry)->SidStart)) {
      acl_size -=
          sizeof(ACCESS_ALLOWED_ACE) + ::GetLengthSid(sid) - sizeof(DWORD);
    }

    if (entry->AceType == ACCESS_DENIED_ACE_TYPE &&
        EqualSid(sid, &((ACCESS_DENIED_ACE*)entry)->SidStart)) {
      acl_size -=
          sizeof(ACCESS_DENIED_ACE) + ::GetLengthSid(sid) - sizeof(DWORD);
    }
  }

  return acl_size;
}

static Status checkAccessWithSD(PSECURITY_DESCRIPTOR sd, mode_t mode) {
  BOOL status = FALSE;
  DWORD access_rights = 0;
  HANDLE process_token = INVALID_HANDLE_VALUE;
  HANDLE impersonate_token = INVALID_HANDLE_VALUE;

  if ((mode & R_OK) == R_OK) {
    access_rights = GENERIC_READ;
  }

  if ((mode & W_OK) == W_OK) {
    access_rights |= GENERIC_WRITE;
  }

  if ((mode & X_OK) == X_OK) {
    access_rights |= GENERIC_EXECUTE;
  }

  status = OpenProcessToken(
      GetCurrentProcess(),
      TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_DUPLICATE | STANDARD_RIGHTS_READ,
      &process_token);
  if (!status) {
    return Status(-1, "OpenProcessToken failed");
  }

  status =
      DuplicateToken(process_token, SecurityImpersonation, &impersonate_token);
  CloseHandle(process_token);

  if (!status) {
    return Status(-1, "DuplicateToken failed");
  }

  GENERIC_MAPPING mapping = {static_cast<ACCESS_MASK>(-1),
                             static_cast<ACCESS_MASK>(-1),
                             static_cast<ACCESS_MASK>(-1),
                             static_cast<ACCESS_MASK>(-1)};
  PRIVILEGE_SET privileges = {0};

  BOOL access_status = FALSE;
  DWORD granted_access = 0;
  DWORD privileges_length = sizeof(privileges);

  mapping.GenericRead = FILE_GENERIC_READ;
  mapping.GenericWrite = FILE_GENERIC_WRITE;
  mapping.GenericExecute = FILE_GENERIC_EXECUTE;
  mapping.GenericAll = FILE_ALL_ACCESS;

  MapGenericMask(&access_rights, &mapping);

  status = AccessCheck(sd,
                       impersonate_token,
                       access_rights,
                       &mapping,
                       &privileges,
                       &privileges_length,
                       &granted_access,
                       &access_status);
  CloseHandle(impersonate_token);

  if (!status) {
    return Status(-1, "AccessCheck failed");
  }

  if (access_status) {
    return Status::success();
  }

  return Status(1, "Bad mode for file");
}

static Status hasAccess(const fs::path& path, mode_t mode) {
  DWORD result = -1;
  PSECURITY_DESCRIPTOR sd = nullptr;
  SECURITY_INFORMATION security_info = OWNER_SECURITY_INFORMATION |
                                       GROUP_SECURITY_INFORMATION |
                                       DACL_SECURITY_INFORMATION;

  result = GetNamedSecurityInfoW(path.wstring().c_str(),
                                 SE_FILE_OBJECT,
                                 security_info,
                                 nullptr,
                                 nullptr,
                                 nullptr,
                                 nullptr,
                                 &sd);
  if (result != ERROR_SUCCESS) {
    return Status(-1, "GetNamedSecurityInfo failed: " + std::to_string(result));
  }

  auto status = checkAccessWithSD(sd, mode);
  LocalFree(sd);

  return status;
}

static Status hasAccess(HANDLE handle, mode_t mode) {
  BOOL status = FALSE;
  DWORD sd_size = 0;
  SECURITY_INFORMATION security_info = OWNER_SECURITY_INFORMATION |
                                       GROUP_SECURITY_INFORMATION |
                                       DACL_SECURITY_INFORMATION;

  status = GetUserObjectSecurity(handle, &security_info, nullptr, 0, &sd_size);
  if (status || (!status && GetLastError() != ERROR_INSUFFICIENT_BUFFER)) {
    return Status(-1, "GetUserObjectSecurity get SD size error");
  }

  std::vector<char> sd_buffer(sd_size, '\0');
  PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)sd_buffer.data();
  status = GetUserObjectSecurity(handle, &security_info, sd, sd_size, &sd_size);
  if (!status) {
    return Status(-1, "GetUserObjectSecurity failed");
  }

  return checkAccessWithSD(sd, mode);
}

static AclObject modifyAcl(PACL acl,
                           PSID target,
                           bool allow_read,
                           bool allow_write,
                           bool allow_exec,
                           bool target_is_owner = false) {
  if (acl == nullptr || !IsValidAcl(acl) || target == nullptr ||
      !IsValidSid(target)) {
    return std::move(AclObject());
  }

  /*
   * On POSIX, all users can view the owner, group, world permissions of a file.
   * To mimic this behavior on Windows, we give READ_CONTROL permissions to
   * everyone. READ_CONTROL allows for an user to read the target file's DACL.
   */
  unsigned long allow_mask = READ_CONTROL;
  unsigned long deny_mask = 0;

  ACL_SIZE_INFORMATION info = {0};
  info.AclBytesInUse = sizeof(ACL);

  if (!GetAclInformation(acl, &info, sizeof(info), AclSizeInformation)) {
    return std::move(AclObject());
  }

  if (target_is_owner) {
    /*
     * Owners should always have the ability to delete the target file and
     * modify the target file's DACL
     */
    allow_mask |= DELETE | WRITE_DAC;
  }

  /*
   * We have defined CHMOD_READ, CHMOD_WRITE, and CHMOD_EXECUTE as combinations
   * of Windows access masks in order to simulate the intended effects of the r,
   * w, x permissions of POSIX. In order to correctly simulate the permissions,
   * any permissions set will be explicitly allowed and any permissions that are
   * unset are explicitly denied. This is all done via access allowed and access
   * denied ACEs.
   *
   * We add additional rights for allow cases because we do not want to pollute
   * the CHMOD_* with overlapping rights. For instance, adding SYNCHRONIZE to
   * both CHMOD_READ and CHMOD_EXECUTE will be problematic if execute is denied.
   * SYNCHRONIZE will be added to a deny access control entry which will prevent
   * even a GENERIC_READ from occurring.
   */

  if (allow_read) {
    allow_mask |= CHMOD_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
  } else {
    deny_mask |= CHMOD_READ;
  }

  if (allow_write) {
    allow_mask |= CHMOD_WRITE | DELETE | SYNCHRONIZE;
  } else {
    // Only deny DELETE if the principal is not the owner
    if (!target_is_owner) {
      deny_mask |= DELETE;
    }

    deny_mask |= CHMOD_WRITE;
  }

  if (allow_exec) {
    allow_mask |= CHMOD_EXECUTE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
  } else {
    deny_mask |= CHMOD_EXECUTE;
  }

  // Only if r and x are denied do we deny FILE_READ_ATTRIBUTES
  if (!allow_read && !allow_exec) {
    deny_mask |= FILE_READ_ATTRIBUTES;
  }

  unsigned long new_acl_size = 0;
  if (allow_read && allow_write && allow_exec) {
    new_acl_size = getNewAclSize(acl, target, info, true, false);
  } else {
    new_acl_size = getNewAclSize(acl, target, info, true, true);
  }

  AclObject new_acl_buffer(new unsigned char[new_acl_size]);
  PACL new_acl = reinterpret_cast<PACL>(new_acl_buffer.get());

  if (!InitializeAcl(new_acl, new_acl_size, ACL_REVISION)) {
    return std::move(AclObject());
  }

  /*
   * Enumerate through the old ACL and copy over all the non-relevant ACEs
   * (read: ACEs that are inherited and not associated with the specified sid).
   * We disregard the ACEs associated with our sid in the old ACL and replace
   * them with updated access masks.
   *
   * The curious bit here is how we order things. In normal Windows ACLs, the
   * ACEs are ordered in a fashion where access denied ACEs have priority to
   * access allowed ACEs. While this is a strong policy, this doesn't fit into
   * our use case and in fact, hurts it. Setting 0600 would prevent even the
   * owner from reading/writing! To counter this, we selectively order the ACEs
   * in our new ACL to fit our needs. This will generate complaints with tools
   * that deal with viewing or modifying the ACL (such as File Explorer).
   */

  unsigned long i = 0;
  LPVOID void_ent = nullptr;
  for (i = 0; i < info.AceCount; i++) {
    if (!GetAce(acl, i, &void_ent)) {
      return std::move(AclObject());
    }

    auto entry = static_cast<PACE_HEADER>(void_ent);
    if ((entry->AceFlags & INHERITED_ACE) == INHERITED_ACE) {
      break;
    }

    auto allowed_ace = reinterpret_cast<ACCESS_ALLOWED_ACE*>(entry);
    auto denied_ace = reinterpret_cast<ACCESS_DENIED_ACE*>(entry);
    if ((entry->AceType == ACCESS_ALLOWED_ACE_TYPE &&
         EqualSid(target, &allowed_ace->SidStart)) ||
        (entry->AceType == ACCESS_DENIED_ACE_TYPE &&
         EqualSid(target, &denied_ace->SidStart))) {
      continue;
    }

    if (!AddAce(new_acl, ACL_REVISION, MAXDWORD, entry, entry->AceSize)) {
      return std::move(AclObject());
    }
  }

  if (deny_mask != 0 &&
      !AddAccessDeniedAce(new_acl, ACL_REVISION, deny_mask, target)) {
    return std::move(AclObject());
  }

  if (allow_mask != 0 &&
      !AddAccessAllowedAce(new_acl, ACL_REVISION, allow_mask, target)) {
    return std::move(AclObject());
  }

  for (; i < info.AceCount; i++) {
    if (!GetAce(acl, i, &void_ent)) {
      return std::move(AclObject());
    }

    auto entry = static_cast<PACE_HEADER>(void_ent);
    if (!AddAce(new_acl, ACL_REVISION, MAXDWORD, void_ent, entry->AceSize)) {
      return std::move(AclObject());
    }
  }

  return std::move(new_acl_buffer);
}

PlatformFile::PlatformFile(const fs::path& path, int mode, int perms)
    : fname_(path) {
  unsigned long access_mask = 0;
  unsigned long flags_and_attrs = 0;
  unsigned long creation_disposition = 0;
  std::unique_ptr<SECURITY_ATTRIBUTES> security_attrs;

  if ((mode & PF_READ) == PF_READ) {
    access_mask |= GENERIC_READ;
  }

  if ((mode & PF_WRITE) == PF_WRITE) {
    access_mask |= GENERIC_WRITE;
  }

  switch (PF_GET_OPTIONS(mode)) {
  case PF_GET_OPTIONS(PF_CREATE_NEW):
    creation_disposition = CREATE_NEW;
    break;
  case PF_GET_OPTIONS(PF_CREATE_ALWAYS):
    creation_disposition = CREATE_ALWAYS;
    break;
  case PF_GET_OPTIONS(PF_OPEN_EXISTING):
    creation_disposition = OPEN_EXISTING;
    break;
  case PF_GET_OPTIONS(PF_OPEN_ALWAYS):
    creation_disposition = OPEN_ALWAYS;
    break;
  case PF_GET_OPTIONS(PF_TRUNCATE):
    creation_disposition = TRUNCATE_EXISTING;
    break;
  default:
    break;
  }

  if ((mode & PF_NONBLOCK) == PF_NONBLOCK) {
    flags_and_attrs |= FILE_FLAG_OVERLAPPED;
    is_nonblock_ = true;
  }

  if (perms != -1) {
    // TODO(#2001): set up a security descriptor based off the perms
  }

  handle_ = ::CreateFileW(fname_.wstring().c_str(),
                          access_mask,
                          FILE_SHARE_READ,
                          security_attrs.get(),
                          creation_disposition,
                          flags_and_attrs,
                          nullptr);

  /// Normally, append is done via the FILE_APPEND_DATA access mask. However,
  /// because we are blanket using GENERIC_WRITE, this will not work. To
  /// compensate, we can emulate the behavior by seeking to the file end
  if (handle_ != INVALID_HANDLE_VALUE && (mode & PF_APPEND) == PF_APPEND) {
    seek(0, PF_SEEK_END);
  }
}

PlatformFile::~PlatformFile() {
  if (handle_ != kInvalidHandle && handle_ != nullptr) {
    // Only cancel IO if we are a non-blocking HANDLE
    if (is_nonblock_) {
      CancelIo(handle_);
    }

    CloseHandle(handle_);
    handle_ = kInvalidHandle;
  }
}

bool PlatformFile::isSpecialFile() const {
  return (GetFileType(handle_) != FILE_TYPE_DISK);
}

std::unique_ptr<BYTE[]> getCurrentUserInfo() {
  HANDLE token = INVALID_HANDLE_VALUE;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &token)) {
    VLOG(1) << "OpenProcessToken failed";
    return nullptr;
  }

  unsigned long size = 0;
  auto ret = GetTokenInformation(token, TokenUser, nullptr, 0, &size);
  if (ret || (!ret && GetLastError() != ERROR_INSUFFICIENT_BUFFER)) {
    CloseHandle(token);
    VLOG(1) << "GetTokenInformation failed (" << GetLastError() << ")";
    return nullptr;
  }

  /// Obtain the TOKEN_USER behind the token handle
  auto ptoken_user = std::make_unique<BYTE[]>(size);

  ret = GetTokenInformation(token, TokenUser, ptoken_user.get(), size, &size);
  CloseHandle(token);

  if (!ret) {
    VLOG(1) << "GetTokenInformation failed (" << GetLastError() << ")";
    return nullptr;
  }

  return ptoken_user;
}

static Status isUserCurrentUser(PSID user) {
  if (!IsValidSid(user)) {
    return Status(-1, "Invalid SID");
  }

  auto ptuSmartPtr = getCurrentUserInfo();

  if (!ptuSmartPtr) {
    return Status::failure(-1, "Accessing current user info failed");
  }

  /// Determine if the current user SID matches that of the specified user
  PTOKEN_USER ptu = reinterpret_cast<PTOKEN_USER>(ptuSmartPtr.get());

  if (EqualSid(user, ptu->User.Sid)) {
    return Status::success();
  }

  return Status(1, "User not current user");
}

Status PlatformFile::isOwnerRoot() const {
  if (!isValid()) {
    return Status(-1, "Invalid file handle value");
  }

  PSID owner = nullptr;
  PSECURITY_DESCRIPTOR sd = nullptr;
  if (GetSecurityInfo(handle_,
                      SE_FILE_OBJECT,
                      OWNER_SECURITY_INFORMATION,
                      &owner,
                      nullptr,
                      nullptr,
                      nullptr,
                      &sd) != ERROR_SUCCESS) {
    return Status(1, "GetSecurityInfo failed");
  }

  SecurityDescriptor sd_wrapper(sd);
  DWORD sid_buff_size = SECURITY_MAX_SID_SIZE;

  std::vector<char> admins_buf(sid_buff_size, '\0');
  auto admins_sid = static_cast<PSID>(admins_buf.data());
  if (!CreateWellKnownSid(
          WinBuiltinAdministratorsSid, nullptr, admins_sid, &sid_buff_size)) {
    return Status(-1, "CreateWellKnownSid failed");
  }

  std::vector<char> system_buf(sid_buff_size, '\0');
  auto system_sid = static_cast<PSID>(system_buf.data());
  if (!CreateWellKnownSid(
          WinLocalSystemSid, nullptr, system_sid, &sid_buff_size)) {
    return Status(-1, "CreateWellKnownSid failed");
  }

  if (EqualSid(owner, admins_sid) || EqualSid(owner, system_sid)) {
    return Status::success();
  }

  return Status(1, "Owner is not in Administrators group or Local System");
}

Status PlatformFile::isOwnerCurrentUser() const {
  if (!isValid()) {
    return Status(-1, "Invalid file handle value");
  }

  PSID owner = nullptr;
  PSECURITY_DESCRIPTOR sd = nullptr;
  if (GetSecurityInfo(handle_,
                      SE_FILE_OBJECT,
                      OWNER_SECURITY_INFORMATION,
                      &owner,
                      nullptr,
                      nullptr,
                      nullptr,
                      &sd) != ERROR_SUCCESS) {
    return Status(-1, "GetSecurityInfo failed");
  }

  SecurityDescriptor sd_wrapper(sd);
  return isUserCurrentUser(owner);
}

Status PlatformFile::isExecutable() const {
  return hasAccess(handle_, X_OK);
}

/*
 * We ensure that only the Administrators group and the SYSTEM
 * account itself have Write privileges on the specified ACL
 */
static Status lowPrivWriteDenied(PACL acl) {
  if (acl == nullptr) {
    return Status(1, "Invalid ACL pointer");
  }

  unsigned long sid_buff_size = SECURITY_MAX_SID_SIZE;

  std::vector<char> system_buffer(sid_buff_size, '\0');
  std::vector<char> administrators_buffer(sid_buff_size, '\0');
  std::vector<char> world_buffer(sid_buff_size, '\0');

  auto system_sid = static_cast<PSID>(system_buffer.data());
  auto admins_sid = static_cast<PSID>(administrators_buffer.data());
  auto world_sid = static_cast<PSID>(world_buffer.data());

  if (!CreateWellKnownSid(
          WinBuiltinAdministratorsSid, nullptr, system_sid, &sid_buff_size)) {
    return Status(-1, "CreateWellKnownSid for Administrators failed");
  }
  if (!CreateWellKnownSid(
          WinLocalSystemSid, nullptr, admins_sid, &sid_buff_size)) {
    return Status(-1, "CreateWellKnownSid for SYSTEM failed");
  }
  if (!CreateWellKnownSid(WinWorldSid, nullptr, world_sid, &sid_buff_size)) {
    return Status(-1, "CreateWellKnownSid for Everyone failed");
  }

  PVOID void_ent = nullptr;
  std::set<PSID> denyWriteSids;
  for (unsigned long i = 0; i < acl->AceCount; i++) {
    if (!GetAce(acl, i, &void_ent)) {
      return Status(-1,
                    "Failed to retrieve ACE when checking safe permissions");
    }
    auto entry = static_cast<PACE_HEADER>(void_ent);

    // If the ACE is a Deny-Write it supercedes subsequent allows, save
    // for the future potential allow entry
    if (entry->AceType == ACCESS_DENIED_ACE_TYPE) {
      auto denied_ace = reinterpret_cast<PACCESS_DENIED_ACE>(entry);

      // We only care about Deny-Write entries, everything else is at the
      // users discretion
      if ((denied_ace->Mask & CHMOD_WRITE) != CHMOD_WRITE) {
        continue;
      }

      // A Deny-Write on Everyone supersedes other allow writes
      if (EqualSid(&denied_ace->SidStart, world_sid)) {
        return Status::success();
      }

      // Stash the Deny-Write ACE to check against future user Allow ACEs
      denyWriteSids.insert(&denied_ace->SidStart);
      continue;
    }

    if (entry->AceType == ACCESS_ALLOWED_ACE_TYPE) {
      auto allowed_ace = reinterpret_cast<PACCESS_ALLOWED_ACE>(entry);

      // Administrators and SYSTEM are allowed Full access
      if (EqualSid(&allowed_ace->SidStart, system_sid) ||
          EqualSid(&allowed_ace->SidStart, admins_sid)) {
        continue;
      }

      /*
       * Deny-Write ACEs supersede Allow-Write ACEs, however this is
       * only the case if the Deny ACE appears _before_ the allow. As
       * such the location of the below equality check is important, and
       * the check for an allow should only come after the check for a deny
       * has been processed.
       */
      auto hasDeny = false;
      for (const auto& p : denyWriteSids) {
        if (EqualSid(&allowed_ace->SidStart, p)) {
          hasDeny = true;
          break;
        }
      }
      if (hasDeny) {
        continue;
      }

      // Check to see if ANY of CHMOD_WRITE rights are set
      if ((allowed_ace->Mask & CHMOD_WRITE) != 0) {
        return Status(-1, "Write ACE was found on ACL");
      }
    }
  }
  return Status::success();
}

Status PlatformFile::hasSafePermissions() const {
  // Get the access control list for the file specified
  PACL file_dacl = nullptr;
  PSECURITY_DESCRIPTOR file_sd = nullptr;
  if (GetSecurityInfo(handle_,
                      SE_FILE_OBJECT,
                      DACL_SECURITY_INFORMATION,
                      nullptr,
                      nullptr,
                      &file_dacl,
                      nullptr,
                      &file_sd) != ERROR_SUCCESS) {
    return Status(-1, "GetSecurityInfo failed");
  }
  SecurityDescriptor file_sd_wrapper(file_sd);

  // Get the access control list for the parent directory
  std::vector<WCHAR> path_buf(MAX_PATH + 1, '\0');
  if (GetFinalPathNameByHandleW(
          handle_, path_buf.data(), MAX_PATH, FILE_NAME_NORMALIZED) == 0) {
    return Status(-1, "GetFinalPathNameByHandle failed");
  }

  if (!PathRemoveFileSpecW(path_buf.data())) {
    return Status(-1, "PathRemoveFileSpec");
  }

  PACL dir_dacl = nullptr;
  PSECURITY_DESCRIPTOR dir_sd = nullptr;
  if (GetNamedSecurityInfoW(path_buf.data(),
                            SE_FILE_OBJECT,
                            DACL_SECURITY_INFORMATION,
                            nullptr,
                            nullptr,
                            &dir_dacl,
                            nullptr,
                            &dir_sd) != ERROR_SUCCESS) {
    return Status(-1, "GetNamedSecurityInfoA failed for dir");
  }
  SecurityDescriptor dir_sd_wrapper(dir_sd);

  /*
   * Check to ensure that no allow write ACEs are found on either
   * the daemon or the parent directory
   */
  auto s = lowPrivWriteDenied(file_dacl);
  if (!s.ok()) {
    return Status(1, "Write ACE was found on the executable");
  }
  s = lowPrivWriteDenied(dir_dacl);
  if (!s.ok()) {
    return Status(1, "Write ACE was found on the parent directory");
  }
  return Status::success();
}

bool PlatformFile::getFileTimes(PlatformTime& times) {
  if (!isValid()) {
    return false;
  }

  return (::GetFileTime(handle_, nullptr, &times.times[0], &times.times[1]) !=
          FALSE);
}

bool PlatformFile::setFileTimes(const PlatformTime& times) {
  if (!isValid()) {
    return false;
  }

  return (::SetFileTime(handle_, nullptr, &times.times[0], &times.times[1]) !=
          FALSE);
}

ssize_t PlatformFile::getOverlappedResultForRead(void* buf,
                                                 size_t requested_size) {
  ssize_t nret = 0;
  DWORD bytes_read = 0;
  DWORD last_error = 0;

  if (::GetOverlappedResult(handle_, &last_read_.overlapped_, &bytes_read, 0)) {
    // Read operation has finished

    // NOTE: We do NOT support situations where the second read operation uses a
    // SMALLER buffer than the initial async request. This will cause the
    // smaller amount to be copied and truncate DATA!
    DWORD size = static_cast<DWORD>(min(requested_size, bytes_read));
    ::memcpy_s(buf, requested_size, last_read_.buffer_.get(), size);

    // Update our cursor
    cursor_ += bytes_read;

    has_pending_io_ = false;
    last_read_.is_active_ = false;
    last_read_.buffer_.reset(nullptr);
    nret = size;
  } else {
    last_error = ::GetLastError();
    if (last_error == ERROR_IO_INCOMPLETE) {
      // Read operation has still not completed
      has_pending_io_ = true;
      last_read_.is_active_ = true;
      nret = -1;
    } else {
      // Error has occurred, just in case, cancel all IO
      ::CancelIo(handle_);

      has_pending_io_ = false;
      last_read_.is_active_ = false;
      last_read_.buffer_.reset(nullptr);
      nret = -1;
    }
  }
  return nret;
}

ssize_t PlatformFile::read(void* buf, size_t nbyte) {
  if (!isValid()) {
    return -1;
  }

  ssize_t nret = -1;
  unsigned long bytes_read = 0;
  unsigned long last_error = 0;

  has_pending_io_ = false;

  if (is_nonblock_) {
    if (last_read_.is_active_) {
      nret = getOverlappedResultForRead(buf, nbyte);
    } else {
      last_read_.overlapped_.Offset = cursor_;
      last_read_.buffer_.reset(new char[nbyte]);
      auto ret = ::ReadFile(handle_,
                            last_read_.buffer_.get(),
                            static_cast<unsigned long>(nbyte),
                            &bytes_read,
                            &last_read_.overlapped_);
      if (ret != 0) {
        memcpy_s(buf, nbyte, last_read_.buffer_.get(), bytes_read);
        nret = bytes_read;
        cursor_ += bytes_read;
      } else {
        last_error = ::GetLastError();
        if (last_error == ERROR_IO_PENDING || last_error == ERROR_MORE_DATA) {
          nret = getOverlappedResultForRead(buf, nbyte);
        }
      }
    }
  } else {
    auto ret = ::ReadFile(
        handle_, buf, static_cast<unsigned long>(nbyte), &bytes_read, nullptr);
    if (ret != 0) {
      nret = bytes_read;
    }
  }
  return nret;
}

ssize_t PlatformFile::write(const void* buf, size_t nbyte) {
  if (!isValid()) {
    return -1;
  }

  ssize_t nret = 0;
  unsigned long bytes_written = 0;
  unsigned long last_error = 0;

  has_pending_io_ = false;

  if (is_nonblock_) {
    AsyncEvent write_event;
    auto ret = ::WriteFile(handle_,
                           buf,
                           static_cast<unsigned long>(nbyte),
                           &bytes_written,
                           &write_event.overlapped_);
    if (ret == 0) {
      last_error = ::GetLastError();
      if (last_error == ERROR_IO_PENDING) {
        ret = ::GetOverlappedResult(
            handle_, &write_event.overlapped_, &bytes_written, 0);
        if (ret == 0) {
          last_error = ::GetLastError();
          if (last_error == ERROR_IO_INCOMPLETE) {
            has_pending_io_ = true;
            // If the write operation has not succeeded, cancel it
            ::CancelIo(handle_);
            nret = -1;
          } else {
            // Error of unknown origin
            TLOG << "Write to " << fname_ << " failed with error ("
                 << GetLastError() << ")";
            nret = -1;
          }
        } else {
          // Write operation succeeded
          nret = bytes_written;
        }
      } else {
        TLOG << "Write to " << fname_ << " failed with error ("
             << GetLastError() << ")";
        nret = -1;
      }
    } else {
      nret = bytes_written;
    }
  } else {
    if (!::WriteFile(handle_,
                     buf,
                     static_cast<unsigned long>(nbyte),
                     &bytes_written,
                     nullptr)) {
      nret = -1;
    } else {
      nret = bytes_written;
    }
  }

  return nret;
}

off_t PlatformFile::seek(off_t offset, SeekMode mode) {
  if (!isValid()) {
    return -1;
  }

  DWORD whence = 0;
  switch (mode) {
  case PF_SEEK_BEGIN:
    whence = FILE_BEGIN;
    break;
  case PF_SEEK_CURRENT:
    whence = FILE_CURRENT;
    break;
  case PF_SEEK_END:
    whence = FILE_END;
    break;
  default:
    break;
  }

  cursor_ = ::SetFilePointer(handle_, offset, nullptr, whence);
  return cursor_;
}

size_t PlatformFile::size() const {
  return ::GetFileSize(handle_, nullptr);
}

bool platformSetSafeDbPerms(const std::string& path) {
  unsigned long sid_size = SECURITY_MAX_SID_SIZE;
  std::vector<char> admins_buf(sid_size);
  PSID admins = static_cast<PSID>(admins_buf.data());
  if (!::CreateWellKnownSid(
          WinBuiltinAdministratorsSid, nullptr, admins, &sid_size)) {
    return false;
  }

  std::vector<char> system_buf(sid_size);
  PSID system = static_cast<PSID>(system_buf.data());
  if (!::CreateWellKnownSid(WinLocalSystemSid, nullptr, system, &sid_size)) {
    return false;
  }

  std::vector<char> world_buf(sid_size);
  PSID world = static_cast<PSID>(world_buf.data());
  if (!::CreateWellKnownSid(WinWorldSid, nullptr, world, &sid_size)) {
    return false;
  }

  EXPLICIT_ACCESSW admins_ea;
  admins_ea.grfAccessMode = SET_ACCESS;
  admins_ea.grfAccessPermissions = GENERIC_ALL;
  admins_ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;

  PTRUSTEE_W trust = static_cast<PTRUSTEE_W>(malloc(sizeof(TRUSTEE_W)));
  BuildTrusteeWithSidW(trust, admins);
  admins_ea.Trustee = *trust;

  // Set the Administrators ACE
  PACL new_dacl = nullptr;
  auto ret = SetEntriesInAclW(1, &admins_ea, nullptr, &new_dacl);
  if (ret != ERROR_SUCCESS) {
    VLOG(1) << "Failed to set DB permissions for Administrators";
    LocalFree(new_dacl);
    free(trust);
    return false;
  }

  // Set the SYSTEM ACE
  EXPLICIT_ACCESSW sys_ea;
  sys_ea.grfAccessMode = SET_ACCESS;
  sys_ea.grfAccessPermissions = GENERIC_ALL;
  sys_ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;

  BuildTrusteeWithSidW(trust, system);
  sys_ea.Trustee = *trust;
  ret = SetEntriesInAclW(1, &sys_ea, new_dacl, &new_dacl);
  if (ret != ERROR_SUCCESS) {
    VLOG(1) << "Failed to set DB permissions for SYSTEM";
    LocalFree(new_dacl);
    free(trust);
    return false;
  }

  // Grant Everyone the ability to read the DACL
  EXPLICIT_ACCESSW world_ea;
  world_ea.grfAccessMode = SET_ACCESS;
  world_ea.grfAccessPermissions = READ_CONTROL;
  world_ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;

  BuildTrusteeWithSidW(trust, world);
  world_ea.Trustee = *trust;
  ret = SetEntriesInAclW(1, &world_ea, new_dacl, &new_dacl);
  if (ret != ERROR_SUCCESS) {
    VLOG(1) << "Failed to set DB permissions for SYSTEM";
    LocalFree(new_dacl);
    free(trust);
    return false;
  }

  std::wstring wide_path = stringToWstring(path.c_str());
  // Apply 'safe' DACL and avoid returning to attempt applying the DACL
  ret = SetNamedSecurityInfoW(
      const_cast<PWSTR>(wide_path.c_str()),
      SE_FILE_OBJECT,
      OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
          DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
      admins,
      admins,
      new_dacl,
      nullptr);
  if (ret != ERROR_SUCCESS) {
    LOG(WARNING) << "Failed to apply safe permssions to the database";
  }
  LocalFree(new_dacl);
  free(trust);
  return true;
}

bool platformChmod(const std::string& path, mode_t perms) {
  PACL dacl = nullptr;
  PSID owner = nullptr;
  PSECURITY_DESCRIPTOR sd = nullptr;

  auto ret = GetNamedSecurityInfoW(stringToWstring(path).c_str(),
                                   SE_FILE_OBJECT,
                                   OWNER_SECURITY_INFORMATION |
                                       GROUP_SECURITY_INFORMATION |
                                       DACL_SECURITY_INFORMATION,
                                   &owner,
                                   nullptr,
                                   &dacl,
                                   nullptr,
                                   &sd);

  if (ret != ERROR_SUCCESS) {
    return false;
  }

  SecurityDescriptor sd_wrapper(sd);

  if (owner == nullptr || dacl == nullptr) {
    return false;
  }

  unsigned long sid_size = SECURITY_MAX_SID_SIZE;
  std::vector<char> world_buf(sid_size);
  PSID world = (PSID)world_buf.data();
  if (!::CreateWellKnownSid(WinWorldSid, nullptr, world, &sid_size)) {
    return false;
  }

  // Modify the 'user' permissions
  PACL acl = nullptr;
  AclObject acl_buffer = modifyAcl(dacl,
                                   owner,
                                   (perms & S_IRUSR) == S_IRUSR,
                                   (perms & S_IWUSR) == S_IWUSR,
                                   (perms & S_IXUSR) == S_IXUSR,
                                   true);
  acl = reinterpret_cast<PACL>(acl_buffer.get());
  if (acl == nullptr) {
    return false;
  }

  // Modify the 'group' permissions
  PVOID void_ent = nullptr;
  for (unsigned long i = 0; i < dacl->AceCount; i++) {
    if (!GetAce(dacl, i, &void_ent)) {
      return false;
    }

    auto ace = static_cast<PACE_HEADER>(void_ent);
    PSID gsid = nullptr;
    if (ace->AceType == ACCESS_ALLOWED_ACE_TYPE) {
      auto allowed_ace = reinterpret_cast<PACCESS_ALLOWED_ACE>(ace);
      gsid = &allowed_ace->SidStart;
    }
    if (ace->AceType == ACCESS_DENIED_ACE_TYPE) {
      auto denied_ace = reinterpret_cast<PACCESS_DENIED_ACE>(ace);
      gsid = &denied_ace->SidStart;
    }

    // We only modify allow or deny ACEs
    if (gsid == nullptr) {
      continue;
    }

    // We process the user and other permissions above and below
    if (EqualSid(gsid, owner) || EqualSid(gsid, world)) {
      continue;
    }

    acl_buffer = modifyAcl(acl,
                           gsid,
                           (perms & S_IRGRP) == S_IRGRP,
                           (perms & S_IWGRP) == S_IWGRP,
                           (perms & S_IXGRP) == S_IXGRP);
    acl = reinterpret_cast<PACL>(acl_buffer.get());
    if (acl == nullptr) {
      return false;
    }
  }

  // Modify the 'other' permissions
  acl_buffer = modifyAcl(acl,
                         world,
                         (perms & S_IROTH) == S_IROTH,
                         (perms & S_IWOTH) == S_IWOTH,
                         (perms & S_IXOTH) == S_IXOTH);
  acl = reinterpret_cast<PACL>(acl_buffer.get());
  if (acl == nullptr) {
    return false;
  }

  std::wstring wide_path = stringToWstring(path);
  // Lastly, apply the permissions to the object
  if (SetNamedSecurityInfoW(const_cast<LPWSTR>(wide_path.c_str()),
                            SE_FILE_OBJECT,
                            DACL_SECURITY_INFORMATION,
                            nullptr,
                            nullptr,
                            acl,
                            nullptr) != ERROR_SUCCESS) {
    return false;
  }
  return true;
}

std::vector<std::string> platformGlob(const std::string& find_path) {
  fs::path full_path(stringToWstring(find_path));

  /*
   * This is a naive implementation of GLOB_TILDE. If the first two characters
   * in the path are '~/' or '~\', we replace it with the value of the
   * USERPROFILE environment variable.
   */
  if (find_path.size() >= 2 && find_path[0] == '~' &&
      (find_path[1] == '/' || find_path[1] == '\\')) {
    auto homedir = getEnvVar("USERPROFILE");
    if (homedir.is_initialized()) {
      full_path = fs::path(stringToWstring(*homedir)) /
                  stringToWstring(find_path.substr(2));
    }
  }

  std::wregex pattern(L".*[*\?].*");

  // This vector will contain all the valid paths at each stage of the
  std::vector<fs::path> valid_paths;
  valid_paths.push_back(fs::path(L""));

  if (full_path.has_parent_path()) {
    /*
     * The provided glob pattern contains more than one directory to traverse.
     * We enumerate each component in the path to generate a list of all
     * possible directories that we need to perform our glob pattern match.
     */
    for (auto& component : full_path.parent_path()) {
      std::vector<fs::path> tmp_valid_paths;

      /*
       * This will enumerate the old set of valid paths and update it by looking
       * for directories matching the specified glob pattern.
       */
      for (auto const& valid_path : valid_paths) {
        if (hasGlobBraces(component.wstring())) {
          /*
           * If the component contains braces, we convert the component into a
           * regex, enumerate through all the directories in the current
           * directory and only mark the ones fitting the regex pattern as
           * valid.
           */
          std::wregex component_pattern(globToRegex(component.wstring()));
          WindowsFindFiles wf(valid_path / L"*");
          for (auto const& file_path : wf.getDirectories()) {
            if (std::regex_match(file_path.filename().wstring(),
                                 component_pattern)) {
              tmp_valid_paths.push_back(file_path);
            }
          }
        } else if (std::regex_match(component.wstring(), pattern)) {
          /*
           * If the component contains wildcard characters such as * or ?, we
           * pass the pattern into the Windows FindFirstFileW function to get a
           * list of valid directories.
           */
          WindowsFindFiles wf(valid_path / component);
          for (auto const& result : wf.getDirectories()) {
            tmp_valid_paths.push_back(result);
          }
        } else {
          /*
           * Since there are no braces and other glob-like wildcards, we are
           * going to append the component to the previous valid path and append
           * the new path to the list
           */
          boost::system::error_code ec;
          if (fs::exists(valid_path / component, ec) &&
              ec.value() == errc::success) {
            fs::path tmp_vpath = component.wstring() != L"."
                                     ? valid_path / component
                                     : valid_path;
            tmp_valid_paths.push_back(tmp_vpath);
          }
        }
      }
      valid_paths.swap(tmp_valid_paths);
    }
  }

  std::vector<std::string> results;

  /*
   * After generating all the valid directories, we enumerate the valid paths
   * and instead of getting back all the glob pattern matching directories, we
   * unrestrict it to get back files as well. We append the file names to the
   * valid paths are return the list.
   */
  for (auto const& valid_path : valid_paths) {
    if (hasGlobBraces(full_path.filename().wstring())) {
      std::wregex component_pattern(
          globToRegex(full_path.filename().wstring()));
      WindowsFindFiles wf(valid_path / L"*");
      for (auto& result : wf.get()) {
        if (std::regex_match(result.filename().wstring(), component_pattern)) {
          auto result_path = result.make_preferred().wstring();

          boost::system::error_code ec;
          if (fs::is_directory(result, ec) && ec.value() == errc::success) {
            result_path += L"\\";
          }
          results.push_back(wstringToString(result_path));
        }
      }
    } else {
      fs::path glob_path = full_path.filename() == L"."
                               ? valid_path
                               : valid_path / full_path.filename();

      WindowsFindFiles wf(glob_path);
      for (auto& result : wf.get()) {
        auto result_path = result.make_preferred().wstring();

        boost::system::error_code ec;
        if (fs::is_directory(result, ec) && ec.value() == errc::success) {
          result_path += L"\\";
        }
        results.push_back(wstringToString(result_path));
      }
    }
  }

  return results;
}

boost::optional<std::string> getHomeDirectory() {
  std::vector<WCHAR> profile(MAX_PATH);
  auto value = getEnvVar("USERPROFILE");
  if (value.is_initialized()) {
    return value;
  } else if (SUCCEEDED(::SHGetFolderPathW(
                 nullptr, CSIDL_PROFILE, nullptr, 0, profile.data()))) {
    return wstringToString(profile.data());
  } else {
    return boost::none;
  }
}

int platformAccess(const std::string& path, mode_t mode) {
  auto status = hasAccess(path, mode);
  if (status.ok()) {
    return 0;
  }

  // Error or invalid access right
  return -1;
}

static bool dirPathsAreEqual(const fs::path& dir1, const fs::path& dir2) {
  // two paths are the same, if both the unique identifier (nFileIndex) and
  // volume serial number are the same.
  // Reference: BY_HANDLE_FILE_INFORMATION structure's nFileIndexLow in MSDN.
  HANDLE path1 = CreateFileW(dir1.wstring().c_str(),
                             GENERIC_READ,
                             FILE_SHARE_READ,
                             nullptr,
                             OPEN_EXISTING,
                             FILE_FLAG_BACKUP_SEMANTICS,
                             nullptr);

  HANDLE path2 = CreateFileW(dir2.wstring().c_str(),
                             GENERIC_READ,
                             FILE_SHARE_READ,
                             nullptr,
                             OPEN_EXISTING,
                             FILE_FLAG_BACKUP_SEMANTICS,
                             nullptr);

  bool result = false;

  if (INVALID_HANDLE_VALUE != path1) {
    if (INVALID_HANDLE_VALUE != path2) {
      BY_HANDLE_FILE_INFORMATION info1 = {0};
      BY_HANDLE_FILE_INFORMATION info2 = {0};
      if (GetFileInformationByHandle(path1, &info1) &&
          GetFileInformationByHandle(path2, &info2)) {
        if (info1.dwVolumeSerialNumber == info2.dwVolumeSerialNumber &&
            info1.nFileIndexHigh == info2.nFileIndexHigh &&
            info1.nFileIndexLow == info2.nFileIndexLow) {
          result = true;
        }
      }

      CloseHandle(path2);
    }

    CloseHandle(path1);
  }

  return result;
}

Status platformIsTmpDir(const fs::path& dir) {
  boost::system::error_code ec;
  if (!dirPathsAreEqual(dir, fs::temp_directory_path(ec))) {
    return Status(1, "Not temp directory");
  }
  return Status::success();
}

Status platformIsFileAccessible(const fs::path& path) {
  boost::system::error_code ec;
  if (fs::is_regular_file(path, ec) && ec.value() == errc::success) {
    return Status::success();
  }
  return Status(1, "Not accessible file");
}

bool platformIsatty(FILE* f) {
  return 0 != _isatty(_fileno(f));
}

boost::optional<FILE*> platformFopen(const std::string& filename,
                                     const std::string& mode) {
  FILE* fp = nullptr;

  auto status = ::fopen_s(&fp, filename.c_str(), mode.c_str());
  if (status != 0) {
    return boost::none;
  }

  if (fp == nullptr) {
    return boost::none;
  }

  return fp;
}

/**
 * @brief The windows implementation introduces a 500ms max wait.
 *
 * We cannot use existing methods to determine the lifespan of the
 * extensions/extensions manager socket. On Windows, the Thrift install is
 * brittle and does not like a quick connect and disconnect. To compensate, we
 * use WaitNamedPipe to determine the existence of a named pipe. If the named
 * pipe does not exist, WaitNamedPipe should error with ERROR_BAD_PATHNAME.
 */
Status socketExists(const fs::path& path, bool remove_socket) {
  DWORD timeout = (remove_socket) ? 0 : 500;
  if (::WaitNamedPipeW(path.wstring().c_str(), timeout) == 0) {
    DWORD error = ::GetLastError();
    if (error == ERROR_BAD_PATHNAME) {
      return Status(1, "Named pipe path is invalid");
    } else if (error == ERROR_FILE_NOT_FOUND) {
      if (remove_socket) {
        return Status(0);
      }

      return Status(1, "Named pipe does not exist");
    }
  }
  return Status::success();
}

std::string getFileAttribStr(unsigned long file_attributes) {
  std::string attribs;

  if (file_attributes & FILE_ATTRIBUTE_ARCHIVE) {
    // Archive file attribute
    attribs.push_back('A');
  }
  if (file_attributes & FILE_ATTRIBUTE_COMPRESSED) {
    // Compressed (Not included in attrib.exe output)
    attribs.push_back('C');
  }
  if (file_attributes & FILE_ATTRIBUTE_ENCRYPTED) {
    // Encrypted (Not included in attrib.exe output)
    attribs.push_back('E');
  }
  if (file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
    // Hidden file attribute
    attribs.push_back('L');
  }
  if (file_attributes & FILE_ATTRIBUTE_HIDDEN) {
    // Hidden file attribute
    attribs.push_back('H');
  }
  if (file_attributes & FILE_ATTRIBUTE_INTEGRITY_STREAM) {
    //
    attribs.push_back('V');
  }
  if (file_attributes & FILE_ATTRIBUTE_NORMAL) {
    // Normal (Not included in attrib.exe output)
    attribs.push_back('N');
  }
  if (file_attributes & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED) {
    // Not content indexed file attribute
    attribs.push_back('I');
  }
  if (file_attributes & FILE_ATTRIBUTE_NO_SCRUB_DATA) {
    // No scrub file attribute
    attribs.push_back('X');
  }
  if (file_attributes & FILE_ATTRIBUTE_OFFLINE) {
    // Offline attribute
    attribs.push_back('O');
  }
  if (file_attributes & FILE_ATTRIBUTE_READONLY) {
    // Read-only file attribute
    attribs.push_back('R');
  }
  if (file_attributes & FILE_ATTRIBUTE_SYSTEM) {
    // System file attribute
    attribs.push_back('S');
  }
  if (file_attributes & FILE_ATTRIBUTE_TEMPORARY) {
    // Temporary file attribute (Not included in attrib.exe output)
    attribs.push_back('T');
  }

  return attribs;
}

std::string lastErrorMessage(unsigned long error_code) {
  LPWSTR msg_buffer = nullptr;

  FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                     FORMAT_MESSAGE_IGNORE_INSERTS,
                 NULL,
                 error_code,
                 MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                 (LPWSTR)&msg_buffer,
                 0,
                 NULL);

  if (msg_buffer != NULL) {
    auto error_message = wstringToString(msg_buffer);
    LocalFree(msg_buffer);
    msg_buffer = nullptr;

    return error_message;
  }

  VLOG(1) << "FormatMessage failed for code (" << std::to_string(error_code)
          << ")";
  return std::string("Error code" + std::to_string(error_code) + "not found");
}

Status platformStat(const fs::path& path, WINDOWS_STAT* wfile_stat) {
  auto FLAGS_AND_ATTRIBUTES = FILE_ATTRIBUTE_ARCHIVE |
                              FILE_ATTRIBUTE_ENCRYPTED | FILE_ATTRIBUTE_HIDDEN |
                              FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_OFFLINE |
                              FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM |
                              FILE_ATTRIBUTE_TEMPORARY;
  // NOTE: cannot call path.wstring(), in the event path was constructed from an
  // std::string, in which case, internal fs::path conversion to wstring will be
  // performed incorrectly.

  if (PathIsDirectoryW(stringToWstring(path.string()).c_str())) {
    FLAGS_AND_ATTRIBUTES |= FILE_FLAG_BACKUP_SEMANTICS;
  }

  // Get the handle of the file object.
  auto file_handle = CreateFileW(stringToWstring(path.string()).c_str(),
                                 GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 nullptr,
                                 OPEN_EXISTING,
                                 FLAGS_AND_ATTRIBUTES,
                                 nullptr);

  // Check GetLastError for CreateFile error code.
  if (file_handle == INVALID_HANDLE_VALUE) {
    CloseHandle(file_handle);
    return Status(-1,
                  "CreateFile failed for " + path.string() + " with " +
                      std::to_string(GetLastError()));
  }

  // Get the owner SID of the file.
  PSID sid_owner = nullptr;
  PSID gid_owner = nullptr;
  PSECURITY_DESCRIPTOR security_descriptor = nullptr;
  auto ret =
      GetSecurityInfo(file_handle,
                      SE_FILE_OBJECT,
                      OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
                      &sid_owner,
                      &gid_owner,
                      NULL,
                      NULL,
                      &security_descriptor);

  // Check GetLastError for GetSecurityInfo error condition.
  if (ret != ERROR_SUCCESS) {
    CloseHandle(file_handle);
    return Status(-1,
                  "GetSecurityInfo failed for " + path.string() + " with " +
                      std::to_string(GetLastError()));
  }

  FILE_BASIC_INFO basic_info;
  BY_HANDLE_FILE_INFORMATION file_info;

  if (GetFileInformationByHandle(file_handle, &file_info) == 0) {
    CloseHandle(file_handle);
    LocalFree(security_descriptor);
    return Status(-1,
                  "GetFileInformationByHandle failed for " + path.string() +
                      " with " + std::to_string(GetLastError()));
  }

  auto file_index =
      (static_cast<unsigned long long>(file_info.nFileIndexHigh) << 32) |
      static_cast<unsigned long long>(file_info.nFileIndexLow);

  std::stringstream stream;
  stream << "0x" << std::setfill('0')
         << std::setw(sizeof(unsigned long long) * 2) << std::hex << file_index;
  std::string file_id(stream.str());

  // Windows has file IDs that are displayed in hex using:
  // fsutil file queryfileid <filename>
  wfile_stat->file_id = file_id;

  // inode is the decimal equivalent of fileid
  wfile_stat->inode = file_index;

  wfile_stat->uid = getUidFromSid(sid_owner);

  wfile_stat->gid = getUidFromSid(gid_owner);

  LocalFree(security_descriptor);

  // Permission bits don't make sense for Windows. Use ntfs_acl_permissions
  // table
  wfile_stat->mode = "-1";

  wfile_stat->symlink = 0;

  auto file_type = GetFileType(file_handle);
  // Try to assign a human readable file type
  switch (file_type) {
  case FILE_TYPE_CHAR: {
    wfile_stat->type = "character";
    break;
  }
  case FILE_TYPE_DISK: {
    if ((file_info.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE) ||
        (file_info.dwFileAttributes & FILE_ATTRIBUTE_NORMAL)) {
      wfile_stat->type = "regular";
    } else if (file_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      wfile_stat->type = "directory";
    } else if (file_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
      wfile_stat->type = "symbolic";
      wfile_stat->symlink = 1;
    } else {
      // This is the type returned from GetFileType -> FILE_TYPE_DISK
      wfile_stat->type = "disk";
    }
    break;
  }
  case FILE_TYPE_PIPE: {
    // If GetNamedPipeInfo fails we assume it's a socket
    (GetNamedPipeInfo(file_handle, 0, 0, 0, 0)) ? wfile_stat->type = "pipe"
                                                : wfile_stat->type = "socket";
    break;
  }
  default: {
    wfile_stat->type = "unknown";
  }
  }

  wfile_stat->attributes = getFileAttribStr(file_info.dwFileAttributes);

  std::stringstream volume_serial;
  volume_serial << std::hex << std::setfill('0') << std::setw(4)
                << HIWORD(file_info.dwVolumeSerialNumber) << "-" << std::setw(4)
                << LOWORD(file_info.dwVolumeSerialNumber);

  wfile_stat->device = file_info.dwVolumeSerialNumber;
  wfile_stat->volume_serial = volume_serial.str();

  LARGE_INTEGER li = {0};
  (GetFileSizeEx(file_handle, &li) == 0) ? wfile_stat->size = -1
                                         : wfile_stat->size = li.QuadPart;

  const char* drive_letter = nullptr;
  auto drive_letter_index = PathGetDriveNumberW(path.wstring().c_str());

  if (drive_letter_index != -1 && kDriveLetters.count(drive_letter_index)) {
    drive_letter = kDriveLetters.at(drive_letter_index).c_str();

    unsigned long sect_per_cluster;
    unsigned long bytes_per_sect;
    unsigned long free_clusters;
    unsigned long total_clusters;

    if (GetDiskFreeSpaceA(drive_letter,
                          &sect_per_cluster,
                          &bytes_per_sect,
                          &free_clusters,
                          &total_clusters) != 0) {
      wfile_stat->block_size = bytes_per_sect;
    } else {
      wfile_stat->block_size = -1;
    }

  } else {
    wfile_stat->block_size = -1;
  }

  wfile_stat->hard_links = file_info.nNumberOfLinks;
  wfile_stat->atime = filetimeToUnixtime(file_info.ftLastAccessTime);
  wfile_stat->mtime = filetimeToUnixtime(file_info.ftLastWriteTime);
  wfile_stat->btime = filetimeToUnixtime(file_info.ftCreationTime);

  // Change time is not available in GetFileInformationByHandle
  ret = GetFileInformationByHandleEx(
      file_handle, FileBasicInfo, &basic_info, sizeof(basic_info));

  (!ret) ? wfile_stat->ctime = -1
         : wfile_stat->ctime = longIntToUnixtime(basic_info.ChangeTime);

  windowsGetVersionInfo(wstringToString(path.wstring()),
                        wfile_stat->product_version,
                        wfile_stat->file_version);

  windowsGetOriginalFilename(wstringToString(path.wstring()),
                             wfile_stat->original_filename);

  CloseHandle(file_handle);

  return Status::success();
}

fs::path getSystemRoot() {
  std::vector<WCHAR> winDirectory(MAX_PATH + 1);
  ZeroMemory(winDirectory.data(), MAX_PATH + 1);
  GetWindowsDirectoryW(winDirectory.data(), MAX_PATH);
  return fs::path(winDirectory.data());
}

Status platformLstat(const std::string& path, struct stat& d_stat) {
  return Status(1);
}
} // namespace osquery
