// In this file is copy+pasted WindowsSupport.h from LLVM 12.0.1-rc1.
// This is so that we can patch it. The upstream sources are incorrectly
// including "llvm/Config/config.h" which is a private header and thus not
// available in the include files distributed with LLVM.
// The patch here changes it to include "llvm/Config/config.h" instead.
// Patch submitted upstream: https://reviews.llvm.org/D103370
#if !defined(_WIN32)
#define LLVM_SUPPORT_WINDOWSSUPPORT_H
#endif

//===- WindowsSupport.h - Common Windows Include File -----------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file defines things specific to Windows implementations.  In addition to
// providing some helpers for working with win32 APIs, this header wraps
// <windows.h> with some portability macros.  Always include WindowsSupport.h
// instead of including <windows.h> directly.
//
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
//=== WARNING: Implementation here must contain only generic Win32 code that
//===          is guaranteed to work on *all* Win32 variants.
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_WINDOWSSUPPORT_H
#define LLVM_SUPPORT_WINDOWSSUPPORT_H

// mingw-w64 tends to define it as 0x0502 in its headers.
#undef _WIN32_WINNT
#undef _WIN32_IE

// Require at least Windows 7 API.
#define _WIN32_WINNT 0x0601
#define _WIN32_IE    0x0800 // MinGW at it again. FIXME: verify if still needed.
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Config/llvm-config.h" // Get build system configuration settings
#include "llvm/Support/Allocator.h"
#include "llvm/Support/Chrono.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/VersionTuple.h"
#include <cassert>
#include <string>
#include <system_error>
#include <windows.h>

// Must be included after windows.h
#include <wincrypt.h>

namespace llvm {

/// Determines if the program is running on Windows 8 or newer. This
/// reimplements one of the helpers in the Windows 8.1 SDK, which are intended
/// to supercede raw calls to GetVersionEx. Old SDKs, Cygwin, and MinGW don't
/// yet have VersionHelpers.h, so we have our own helper.
bool RunningWindows8OrGreater();

/// Returns the Windows version as Major.Minor.0.BuildNumber. Uses
/// RtlGetVersion or GetVersionEx under the hood depending on what is available.
/// GetVersionEx is deprecated, but this API exposes the build number which can
/// be useful for working around certain kernel bugs.
llvm::VersionTuple GetWindowsOSVersion();

bool MakeErrMsg(std::string *ErrMsg, const std::string &prefix);

// Include GetLastError() in a fatal error message.
LLVM_ATTRIBUTE_NORETURN inline void ReportLastErrorFatal(const char *Msg) {
  std::string ErrMsg;
  MakeErrMsg(&ErrMsg, Msg);
  llvm::report_fatal_error(ErrMsg);
}

template <typename HandleTraits>
class ScopedHandle {
  typedef typename HandleTraits::handle_type handle_type;
  handle_type Handle;

  ScopedHandle(const ScopedHandle &other) = delete;
  void operator=(const ScopedHandle &other) = delete;
public:
  ScopedHandle()
    : Handle(HandleTraits::GetInvalid()) {}

  explicit ScopedHandle(handle_type h)
    : Handle(h) {}

  ~ScopedHandle() {
    if (HandleTraits::IsValid(Handle))
      HandleTraits::Close(Handle);
  }

  handle_type take() {
    handle_type t = Handle;
    Handle = HandleTraits::GetInvalid();
    return t;
  }

  ScopedHandle &operator=(handle_type h) {
    if (HandleTraits::IsValid(Handle))
      HandleTraits::Close(Handle);
    Handle = h;
    return *this;
  }

  // True if Handle is valid.
  explicit operator bool() const {
    return HandleTraits::IsValid(Handle) ? true : false;
  }

  operator handle_type() const {
    return Handle;
  }
};

struct CommonHandleTraits {
  typedef HANDLE handle_type;

  static handle_type GetInvalid() {
    return INVALID_HANDLE_VALUE;
  }

  static void Close(handle_type h) {
    ::CloseHandle(h);
  }

  static bool IsValid(handle_type h) {
    return h != GetInvalid();
  }
};

struct JobHandleTraits : CommonHandleTraits {
  static handle_type GetInvalid() {
    return NULL;
  }
};

struct CryptContextTraits : CommonHandleTraits {
  typedef HCRYPTPROV handle_type;

  static handle_type GetInvalid() {
    return 0;
  }

  static void Close(handle_type h) {
    ::CryptReleaseContext(h, 0);
  }

  static bool IsValid(handle_type h) {
    return h != GetInvalid();
  }
};

struct RegTraits : CommonHandleTraits {
  typedef HKEY handle_type;

  static handle_type GetInvalid() {
    return NULL;
  }

  static void Close(handle_type h) {
    ::RegCloseKey(h);
  }

  static bool IsValid(handle_type h) {
    return h != GetInvalid();
  }
};

struct FindHandleTraits : CommonHandleTraits {
  static void Close(handle_type h) {
    ::FindClose(h);
  }
};

struct FileHandleTraits : CommonHandleTraits {};

typedef ScopedHandle<CommonHandleTraits> ScopedCommonHandle;
typedef ScopedHandle<FileHandleTraits>   ScopedFileHandle;
typedef ScopedHandle<CryptContextTraits> ScopedCryptContext;
typedef ScopedHandle<RegTraits>          ScopedRegHandle;
typedef ScopedHandle<FindHandleTraits>   ScopedFindHandle;
typedef ScopedHandle<JobHandleTraits>    ScopedJobHandle;

template <class T>
class SmallVectorImpl;

template <class T>
typename SmallVectorImpl<T>::const_pointer
c_str(SmallVectorImpl<T> &str) {
  str.push_back(0);
  str.pop_back();
  return str.data();
}

namespace sys {

inline std::chrono::nanoseconds toDuration(FILETIME Time) {
  ULARGE_INTEGER TimeInteger;
  TimeInteger.LowPart = Time.dwLowDateTime;
  TimeInteger.HighPart = Time.dwHighDateTime;

  // FILETIME's are # of 100 nanosecond ticks (1/10th of a microsecond)
  return std::chrono::nanoseconds(100 * TimeInteger.QuadPart);
}

inline TimePoint<> toTimePoint(FILETIME Time) {
  ULARGE_INTEGER TimeInteger;
  TimeInteger.LowPart = Time.dwLowDateTime;
  TimeInteger.HighPart = Time.dwHighDateTime;

  // Adjust for different epoch
  TimeInteger.QuadPart -= 11644473600ll * 10000000;

  // FILETIME's are # of 100 nanosecond ticks (1/10th of a microsecond)
  return TimePoint<>(std::chrono::nanoseconds(100 * TimeInteger.QuadPart));
}

inline FILETIME toFILETIME(TimePoint<> TP) {
  ULARGE_INTEGER TimeInteger;
  TimeInteger.QuadPart = TP.time_since_epoch().count() / 100;
  TimeInteger.QuadPart += 11644473600ll * 10000000;

  FILETIME Time;
  Time.dwLowDateTime = TimeInteger.LowPart;
  Time.dwHighDateTime = TimeInteger.HighPart;
  return Time;
}

namespace windows {
// Returns command line arguments. Unlike arguments given to main(),
// this function guarantees that the returned arguments are encoded in
// UTF-8 regardless of the current code page setting.
std::error_code GetCommandLineArguments(SmallVectorImpl<const char *> &Args,
                                        BumpPtrAllocator &Alloc);

/// Convert UTF-8 path to a suitable UTF-16 path for use with the Win32 Unicode
/// File API.
std::error_code widenPath(const Twine &Path8, SmallVectorImpl<wchar_t> &Path16,
                          size_t MaxPathLen = MAX_PATH);

} // end namespace windows
} // end namespace sys
} // end namespace llvm.

#endif

//===-- llvm-ar.cpp - LLVM archive librarian utility ----------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Builds up (relatively) standard unix archive files (.a) containing LLVM
// bitcode or other files.
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringSwitch.h"
#include "llvm/ADT/Triple.h"
#include "llvm/BinaryFormat/Magic.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/Object/Archive.h"
#include "llvm/Object/ArchiveWriter.h"
#include "llvm/Object/IRObjectFile.h"
#include "llvm/Object/MachO.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/SymbolicFile.h"
#include "llvm/Support/Chrono.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ConvertUTF.h"
#include "llvm/Support/Errc.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/Host.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/LineIterator.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/Process.h"
#include "llvm/Support/StringSaver.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/WithColor.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/ToolDrivers/llvm-dlltool/DlltoolDriver.h"
#include "llvm/ToolDrivers/llvm-lib/LibDriver.h"

#if !defined(_MSC_VER) && !defined(__MINGW32__)
#include <unistd.h>
#else
#include <io.h>
#endif

#ifdef _WIN32
#include "llvm/Support/Windows/WindowsSupport.h"
#endif

using namespace llvm;

// The name this program was invoked as.
static StringRef ToolName;

// The basename of this program.
static StringRef Stem;

const char RanlibHelp[] = R"(OVERVIEW: LLVM Ranlib (llvm-ranlib)

  This program generates an index to speed access to archives

USAGE: llvm-ranlib <archive-file>

OPTIONS:
  -h --help             - Display available options
  -v --version          - Display the version of this program
  -D                    - Use zero for timestamps and uids/gids (default)
  -U                    - Use actual timestamps and uids/gids
)";

const char ArHelp[] = R"(OVERVIEW: LLVM Archiver

USAGE: llvm-ar [options] [-]<operation>[modifiers] [relpos] [count] <archive> [files]
       llvm-ar -M [<mri-script]

OPTIONS:
  --format              - archive format to create
    =default            -   default
    =gnu                -   gnu
    =darwin             -   darwin
    =bsd                -   bsd
  --plugin=<string>     - ignored for compatibility
  -h --help             - display this help and exit
  --rsp-quoting         - quoting style for response files
    =posix              -   posix
    =windows            -   windows
  --version             - print the version and exit
  @<file>               - read options from <file>

OPERATIONS:
  d - delete [files] from the archive
  m - move [files] in the archive
  p - print [files] found in the archive
  q - quick append [files] to the archive
  r - replace or insert [files] into the archive
  s - act as ranlib
  t - display contents of archive
  x - extract [files] from the archive

MODIFIERS:
  [a] - put [files] after [relpos]
  [b] - put [files] before [relpos] (same as [i])
  [c] - do not warn if archive had to be created
  [D] - use zero for timestamps and uids/gids (default)
  [h] - display this help and exit
  [i] - put [files] before [relpos] (same as [b])
  [l] - ignored for compatibility
  [L] - add archive's contents
  [N] - use instance [count] of name
  [o] - preserve original dates
  [O] - display member offsets
  [P] - use full names when matching (implied for thin archives)
  [s] - create an archive index (cf. ranlib)
  [S] - do not build a symbol table
  [T] - create a thin archive
  [u] - update only [files] newer than archive contents
  [U] - use actual timestamps and uids/gids
  [v] - be verbose about actions taken
  [V] - display the version and exit
)";

static void printHelpMessage() {
  if (Stem.contains_insensitive("ranlib"))
    outs() << RanlibHelp;
  else if (Stem.contains_insensitive("ar"))
    outs() << ArHelp;
}

static unsigned MRILineNumber;
static bool ParsingMRIScript;

// Show the error plus the usage message, and exit.
LLVM_ATTRIBUTE_NORETURN static void badUsage(Twine Error) {
  WithColor::error(errs(), ToolName) << Error << "\n";
  printHelpMessage();
  exit(1);
}

// Show the error message and exit.
LLVM_ATTRIBUTE_NORETURN static void fail(Twine Error) {
  if (ParsingMRIScript) {
    WithColor::error(errs(), ToolName)
        << "script line " << MRILineNumber << ": " << Error << "\n";
  } else {
    WithColor::error(errs(), ToolName) << Error << "\n";
  }
  exit(1);
}

static void failIfError(std::error_code EC, Twine Context = "") {
  if (!EC)
    return;

  std::string ContextStr = Context.str();
  if (ContextStr.empty())
    fail(EC.message());
  fail(Context + ": " + EC.message());
}

static void failIfError(Error E, Twine Context = "") {
  if (!E)
    return;

  handleAllErrors(std::move(E), [&](const llvm::ErrorInfoBase &EIB) {
    std::string ContextStr = Context.str();
    if (ContextStr.empty())
      fail(EIB.message());
    fail(Context + ": " + EIB.message());
  });
}

static SmallVector<const char *, 256> PositionalArgs;

static bool MRI;

namespace {
enum Format { Default, GNU, BSD, DARWIN, Unknown };
}

static Format FormatType = Default;

static std::string Options;

// This enumeration delineates the kinds of operations on an archive
// that are permitted.
enum ArchiveOperation {
  Print,           ///< Print the contents of the archive
  Delete,          ///< Delete the specified members
  Move,            ///< Move members to end or as given by {a,b,i} modifiers
  QuickAppend,     ///< Quickly append to end of archive
  ReplaceOrInsert, ///< Replace or Insert members
  DisplayTable,    ///< Display the table of contents
  Extract,         ///< Extract files back to file system
  CreateSymTab     ///< Create a symbol table in an existing archive
};

// Modifiers to follow operation to vary behavior
static bool AddAfter = false;             ///< 'a' modifier
static bool AddBefore = false;            ///< 'b' modifier
static bool Create = false;               ///< 'c' modifier
static bool OriginalDates = false;        ///< 'o' modifier
static bool DisplayMemberOffsets = false; ///< 'O' modifier
static bool CompareFullPath = false;      ///< 'P' modifier
static bool OnlyUpdate = false;           ///< 'u' modifier
static bool Verbose = false;              ///< 'v' modifier
static bool Symtab = true;                ///< 's' modifier
static bool Deterministic = true;         ///< 'D' and 'U' modifiers
static bool Thin = false;                 ///< 'T' modifier
static bool AddLibrary = false;           ///< 'L' modifier

// Relative Positional Argument (for insert/move). This variable holds
// the name of the archive member to which the 'a', 'b' or 'i' modifier
// refers. Only one of 'a', 'b' or 'i' can be specified so we only need
// one variable.
static std::string RelPos;

// Count parameter for 'N' modifier. This variable specifies which file should
// match for extract/delete operations when there are multiple matches. This is
// 1-indexed. A value of 0 is invalid, and implies 'N' is not used.
static int CountParam = 0;

// This variable holds the name of the archive file as given on the
// command line.
static std::string ArchiveName;

static std::vector<std::unique_ptr<MemoryBuffer>> ArchiveBuffers;
static std::vector<std::unique_ptr<object::Archive>> Archives;

// This variable holds the list of member files to proecess, as given
// on the command line.
static std::vector<StringRef> Members;

// Static buffer to hold StringRefs.
static BumpPtrAllocator Alloc;

// Extract the member filename from the command line for the [relpos] argument
// associated with a, b, and i modifiers
static void getRelPos() {
  if (PositionalArgs.empty())
    fail("expected [relpos] for 'a', 'b', or 'i' modifier");
  RelPos = PositionalArgs[0];
  PositionalArgs.erase(PositionalArgs.begin());
}

// Extract the parameter from the command line for the [count] argument
// associated with the N modifier
static void getCountParam() {
  if (PositionalArgs.empty())
    badUsage("expected [count] for 'N' modifier");
  auto CountParamArg = StringRef(PositionalArgs[0]);
  if (CountParamArg.getAsInteger(10, CountParam))
    badUsage("value for [count] must be numeric, got: " + CountParamArg);
  if (CountParam < 1)
    badUsage("value for [count] must be positive, got: " + CountParamArg);
  PositionalArgs.erase(PositionalArgs.begin());
}

// Get the archive file name from the command line
static void getArchive() {
  if (PositionalArgs.empty())
    badUsage("an archive name must be specified");
  ArchiveName = PositionalArgs[0];
  PositionalArgs.erase(PositionalArgs.begin());
}

static object::Archive &readLibrary(const Twine &Library) {
  auto BufOrErr = MemoryBuffer::getFile(Library, -1, false);
  failIfError(BufOrErr.getError(), "could not open library " + Library);
  ArchiveBuffers.push_back(std::move(*BufOrErr));
  auto LibOrErr =
      object::Archive::create(ArchiveBuffers.back()->getMemBufferRef());
  failIfError(errorToErrorCode(LibOrErr.takeError()),
              "could not parse library");
  Archives.push_back(std::move(*LibOrErr));
  return *Archives.back();
}

static void runMRIScript();

// Parse the command line options as presented and return the operation
// specified. Process all modifiers and check to make sure that constraints on
// modifier/operation pairs have not been violated.
static ArchiveOperation parseCommandLine() {
  if (MRI) {
    if (!PositionalArgs.empty() || !Options.empty())
      badUsage("cannot mix -M and other options");
    runMRIScript();
  }

  // Keep track of number of operations. We can only specify one
  // per execution.
  unsigned NumOperations = 0;

  // Keep track of the number of positional modifiers (a,b,i). Only
  // one can be specified.
  unsigned NumPositional = 0;

  // Keep track of which operation was requested
  ArchiveOperation Operation;

  bool MaybeJustCreateSymTab = false;

  for (unsigned i = 0; i < Options.size(); ++i) {
    switch (Options[i]) {
    case 'd':
      ++NumOperations;
      Operation = Delete;
      break;
    case 'm':
      ++NumOperations;
      Operation = Move;
      break;
    case 'p':
      ++NumOperations;
      Operation = Print;
      break;
    case 'q':
      ++NumOperations;
      Operation = QuickAppend;
      break;
    case 'r':
      ++NumOperations;
      Operation = ReplaceOrInsert;
      break;
    case 't':
      ++NumOperations;
      Operation = DisplayTable;
      break;
    case 'x':
      ++NumOperations;
      Operation = Extract;
      break;
    case 'c':
      Create = true;
      break;
    case 'l': /* accepted but unused */
      break;
    case 'o':
      OriginalDates = true;
      break;
    case 'O':
      DisplayMemberOffsets = true;
      break;
    case 'P':
      CompareFullPath = true;
      break;
    case 's':
      Symtab = true;
      MaybeJustCreateSymTab = true;
      break;
    case 'S':
      Symtab = false;
      break;
    case 'u':
      OnlyUpdate = true;
      break;
    case 'v':
      Verbose = true;
      break;
    case 'a':
      getRelPos();
      AddAfter = true;
      NumPositional++;
      break;
    case 'b':
      getRelPos();
      AddBefore = true;
      NumPositional++;
      break;
    case 'i':
      getRelPos();
      AddBefore = true;
      NumPositional++;
      break;
    case 'D':
      Deterministic = true;
      break;
    case 'U':
      Deterministic = false;
      break;
    case 'N':
      getCountParam();
      break;
    case 'T':
      Thin = true;
      // Thin archives store path names, so P should be forced.
      CompareFullPath = true;
      break;
    case 'L':
      AddLibrary = true;
      break;
    case 'V':
      cl::PrintVersionMessage();
      exit(0);
    case 'h':
      printHelpMessage();
      exit(0);
    default:
      badUsage(std::string("unknown option ") + Options[i]);
    }
  }

  // At this point, the next thing on the command line must be
  // the archive name.
  getArchive();

  // Everything on the command line at this point is a member.
  Members.assign(PositionalArgs.begin(), PositionalArgs.end());

  if (NumOperations == 0 && MaybeJustCreateSymTab) {
    NumOperations = 1;
    Operation = CreateSymTab;
    if (!Members.empty())
      badUsage("the 's' operation takes only an archive as argument");
  }

  // Perform various checks on the operation/modifier specification
  // to make sure we are dealing with a legal request.
  if (NumOperations == 0)
    badUsage("you must specify at least one of the operations");
  if (NumOperations > 1)
    badUsage("only one operation may be specified");
  if (NumPositional > 1)
    badUsage("you may only specify one of 'a', 'b', and 'i' modifiers");
  if (AddAfter || AddBefore)
    if (Operation != Move && Operation != ReplaceOrInsert)
      badUsage("the 'a', 'b' and 'i' modifiers can only be specified with "
               "the 'm' or 'r' operations");
  if (CountParam)
    if (Operation != Extract && Operation != Delete)
      badUsage("the 'N' modifier can only be specified with the 'x' or 'd' "
               "operations");
  if (OriginalDates && Operation != Extract)
    badUsage("the 'o' modifier is only applicable to the 'x' operation");
  if (OnlyUpdate && Operation != ReplaceOrInsert)
    badUsage("the 'u' modifier is only applicable to the 'r' operation");
  if (AddLibrary && Operation != QuickAppend)
    badUsage("the 'L' modifier is only applicable to the 'q' operation");

  // Return the parsed operation to the caller
  return Operation;
}

// Implements the 'p' operation. This function traverses the archive
// looking for members that match the path list.
static void doPrint(StringRef Name, const object::Archive::Child &C) {
  if (Verbose)
    outs() << "Printing " << Name << "\n";

  Expected<StringRef> DataOrErr = C.getBuffer();
  failIfError(DataOrErr.takeError());
  StringRef Data = *DataOrErr;
  outs().write(Data.data(), Data.size());
}

// Utility function for printing out the file mode when the 't' operation is in
// verbose mode.
static void printMode(unsigned mode) {
  outs() << ((mode & 004) ? "r" : "-");
  outs() << ((mode & 002) ? "w" : "-");
  outs() << ((mode & 001) ? "x" : "-");
}

// Implement the 't' operation. This function prints out just
// the file names of each of the members. However, if verbose mode is requested
// ('v' modifier) then the file type, permission mode, user, group, size, and
// modification time are also printed.
static void doDisplayTable(StringRef Name, const object::Archive::Child &C) {
  if (Verbose) {
    Expected<sys::fs::perms> ModeOrErr = C.getAccessMode();
    failIfError(ModeOrErr.takeError());
    sys::fs::perms Mode = ModeOrErr.get();
    printMode((Mode >> 6) & 007);
    printMode((Mode >> 3) & 007);
    printMode(Mode & 007);
    Expected<unsigned> UIDOrErr = C.getUID();
    failIfError(UIDOrErr.takeError());
    outs() << ' ' << UIDOrErr.get();
    Expected<unsigned> GIDOrErr = C.getGID();
    failIfError(GIDOrErr.takeError());
    outs() << '/' << GIDOrErr.get();
    Expected<uint64_t> Size = C.getSize();
    failIfError(Size.takeError());
    outs() << ' ' << format("%6llu", Size.get());
    auto ModTimeOrErr = C.getLastModified();
    failIfError(ModTimeOrErr.takeError());
    // Note: formatv() only handles the default TimePoint<>, which is in
    // nanoseconds.
    // TODO: fix format_provider<TimePoint<>> to allow other units.
    sys::TimePoint<> ModTimeInNs = ModTimeOrErr.get();
    outs() << ' ' << formatv("{0:%b %e %H:%M %Y}", ModTimeInNs);
    outs() << ' ';
  }

  if (C.getParent()->isThin()) {
    if (!sys::path::is_absolute(Name)) {
      StringRef ParentDir = sys::path::parent_path(ArchiveName);
      if (!ParentDir.empty())
        outs() << sys::path::convert_to_slash(ParentDir) << '/';
    }
    outs() << Name;
  } else {
    outs() << Name;
    if (DisplayMemberOffsets)
      outs() << " 0x" << utohexstr(C.getDataOffset(), true);
  }
  outs() << '\n';
}

static std::string normalizePath(StringRef Path) {
  return CompareFullPath ? sys::path::convert_to_slash(Path)
                         : std::string(sys::path::filename(Path));
}

static bool comparePaths(StringRef Path1, StringRef Path2) {
// When on Windows this function calls CompareStringOrdinal
// as Windows file paths are case-insensitive.
// CompareStringOrdinal compares two Unicode strings for
// binary equivalence and allows for case insensitivity.
#ifdef _WIN32
  SmallVector<wchar_t, 128> WPath1, WPath2;
  failIfError(sys::windows::UTF8ToUTF16(normalizePath(Path1), WPath1));
  failIfError(sys::windows::UTF8ToUTF16(normalizePath(Path2), WPath2));

  return CompareStringOrdinal(WPath1.data(), WPath1.size(), WPath2.data(),
                              WPath2.size(), true) == CSTR_EQUAL;
#else
  return normalizePath(Path1) == normalizePath(Path2);
#endif
}

// Implement the 'x' operation. This function extracts files back to the file
// system.
static void doExtract(StringRef Name, const object::Archive::Child &C) {
  // Retain the original mode.
  Expected<sys::fs::perms> ModeOrErr = C.getAccessMode();
  failIfError(ModeOrErr.takeError());
  sys::fs::perms Mode = ModeOrErr.get();

  llvm::StringRef outputFilePath = sys::path::filename(Name);
  if (Verbose)
    outs() << "x - " << outputFilePath << '\n';

  int FD;
  failIfError(sys::fs::openFileForWrite(outputFilePath, FD,
                                        sys::fs::CD_CreateAlways,
                                        sys::fs::OF_None, Mode),
              Name);

  {
    raw_fd_ostream file(FD, false);

    // Get the data and its length
    Expected<StringRef> BufOrErr = C.getBuffer();
    failIfError(BufOrErr.takeError());
    StringRef Data = BufOrErr.get();

    // Write the data.
    file.write(Data.data(), Data.size());
  }

  // If we're supposed to retain the original modification times, etc. do so
  // now.
  if (OriginalDates) {
    auto ModTimeOrErr = C.getLastModified();
    failIfError(ModTimeOrErr.takeError());
    failIfError(
        sys::fs::setLastAccessAndModificationTime(FD, ModTimeOrErr.get()));
  }

  if (close(FD))
    fail("Could not close the file");
}

static bool shouldCreateArchive(ArchiveOperation Op) {
  switch (Op) {
  case Print:
  case Delete:
  case Move:
  case DisplayTable:
  case Extract:
  case CreateSymTab:
    return false;

  case QuickAppend:
  case ReplaceOrInsert:
    return true;
  }

  llvm_unreachable("Missing entry in covered switch.");
}

static void performReadOperation(ArchiveOperation Operation,
                                 object::Archive *OldArchive) {
  if (Operation == Extract && OldArchive->isThin())
    fail("extracting from a thin archive is not supported");

  bool Filter = !Members.empty();
  StringMap<int> MemberCount;
  {
    Error Err = Error::success();
    for (auto &C : OldArchive->children(Err)) {
      Expected<StringRef> NameOrErr = C.getName();
      failIfError(NameOrErr.takeError());
      StringRef Name = NameOrErr.get();

      if (Filter) {
        auto I = find_if(Members, [Name](StringRef Path) {
          return comparePaths(Name, Path);
        });
        if (I == Members.end())
          continue;
        if (CountParam && ++MemberCount[Name] != CountParam)
          continue;
        Members.erase(I);
      }

      switch (Operation) {
      default:
        llvm_unreachable("Not a read operation");
      case Print:
        doPrint(Name, C);
        break;
      case DisplayTable:
        doDisplayTable(Name, C);
        break;
      case Extract:
        doExtract(Name, C);
        break;
      }
    }
    failIfError(std::move(Err));
  }

  if (Members.empty())
    return;
  for (StringRef Name : Members)
    WithColor::error(errs(), ToolName) << "'" << Name << "' was not found\n";
  exit(1);
}

static void addChildMember(std::vector<NewArchiveMember> &Members,
                           const object::Archive::Child &M,
                           bool FlattenArchive = false) {
  if (Thin && !M.getParent()->isThin())
    fail("cannot convert a regular archive to a thin one");
  Expected<NewArchiveMember> NMOrErr =
      NewArchiveMember::getOldMember(M, Deterministic);
  failIfError(NMOrErr.takeError());
  // If the child member we're trying to add is thin, use the path relative to
  // the archive it's in, so the file resolves correctly.
  if (Thin && FlattenArchive) {
    StringSaver Saver(Alloc);
    Expected<std::string> FileNameOrErr(M.getName());
    failIfError(FileNameOrErr.takeError());
    if (sys::path::is_absolute(*FileNameOrErr)) {
      NMOrErr->MemberName = Saver.save(sys::path::convert_to_slash(*FileNameOrErr));
    } else {
      FileNameOrErr = M.getFullName();
      failIfError(FileNameOrErr.takeError());
      Expected<std::string> PathOrErr =
          computeArchiveRelativePath(ArchiveName, *FileNameOrErr);
      NMOrErr->MemberName = Saver.save(
          PathOrErr ? *PathOrErr : sys::path::convert_to_slash(*FileNameOrErr));
    }
  }
  if (FlattenArchive &&
      identify_magic(NMOrErr->Buf->getBuffer()) == file_magic::archive) {
    Expected<std::string> FileNameOrErr = M.getFullName();
    failIfError(FileNameOrErr.takeError());
    object::Archive &Lib = readLibrary(*FileNameOrErr);
    // When creating thin archives, only flatten if the member is also thin.
    if (!Thin || Lib.isThin()) {
      Error Err = Error::success();
      // Only Thin archives are recursively flattened.
      for (auto &Child : Lib.children(Err))
        addChildMember(Members, Child, /*FlattenArchive=*/Thin);
      failIfError(std::move(Err));
      return;
    }
  }
  Members.push_back(std::move(*NMOrErr));
}

static void addMember(std::vector<NewArchiveMember> &Members,
                      StringRef FileName, bool FlattenArchive = false) {
  Expected<NewArchiveMember> NMOrErr =
      NewArchiveMember::getFile(FileName, Deterministic);
  failIfError(NMOrErr.takeError(), FileName);
  StringSaver Saver(Alloc);
  // For regular archives, use the basename of the object path for the member
  // name. For thin archives, use the full relative paths so the file resolves
  // correctly.
  if (!Thin) {
    NMOrErr->MemberName = sys::path::filename(NMOrErr->MemberName);
  } else {
    if (sys::path::is_absolute(FileName))
      NMOrErr->MemberName = Saver.save(sys::path::convert_to_slash(FileName));
    else {
      Expected<std::string> PathOrErr =
          computeArchiveRelativePath(ArchiveName, FileName);
      NMOrErr->MemberName = Saver.save(
          PathOrErr ? *PathOrErr : sys::path::convert_to_slash(FileName));
    }
  }

  if (FlattenArchive &&
      identify_magic(NMOrErr->Buf->getBuffer()) == file_magic::archive) {
    object::Archive &Lib = readLibrary(FileName);
    // When creating thin archives, only flatten if the member is also thin.
    if (!Thin || Lib.isThin()) {
      Error Err = Error::success();
      // Only Thin archives are recursively flattened.
      for (auto &Child : Lib.children(Err))
        addChildMember(Members, Child, /*FlattenArchive=*/Thin);
      failIfError(std::move(Err));
      return;
    }
  }
  Members.push_back(std::move(*NMOrErr));
}

enum InsertAction {
  IA_AddOldMember,
  IA_AddNewMember,
  IA_Delete,
  IA_MoveOldMember,
  IA_MoveNewMember
};

static InsertAction computeInsertAction(ArchiveOperation Operation,
                                        const object::Archive::Child &Member,
                                        StringRef Name,
                                        std::vector<StringRef>::iterator &Pos,
                                        StringMap<int> &MemberCount) {
  if (Operation == QuickAppend || Members.empty())
    return IA_AddOldMember;
  auto MI = find_if(
      Members, [Name](StringRef Path) { return comparePaths(Name, Path); });

  if (MI == Members.end())
    return IA_AddOldMember;

  Pos = MI;

  if (Operation == Delete) {
    if (CountParam && ++MemberCount[Name] != CountParam)
      return IA_AddOldMember;
    return IA_Delete;
  }

  if (Operation == Move)
    return IA_MoveOldMember;

  if (Operation == ReplaceOrInsert) {
    if (!OnlyUpdate) {
      if (RelPos.empty())
        return IA_AddNewMember;
      return IA_MoveNewMember;
    }

    // We could try to optimize this to a fstat, but it is not a common
    // operation.
    sys::fs::file_status Status;
    failIfError(sys::fs::status(*MI, Status), *MI);
    auto ModTimeOrErr = Member.getLastModified();
    failIfError(ModTimeOrErr.takeError());
    if (Status.getLastModificationTime() < ModTimeOrErr.get()) {
      if (RelPos.empty())
        return IA_AddOldMember;
      return IA_MoveOldMember;
    }

    if (RelPos.empty())
      return IA_AddNewMember;
    return IA_MoveNewMember;
  }
  llvm_unreachable("No such operation");
}

// We have to walk this twice and computing it is not trivial, so creating an
// explicit std::vector is actually fairly efficient.
static std::vector<NewArchiveMember>
computeNewArchiveMembers(ArchiveOperation Operation,
                         object::Archive *OldArchive) {
  std::vector<NewArchiveMember> Ret;
  std::vector<NewArchiveMember> Moved;
  int InsertPos = -1;
  if (OldArchive) {
    Error Err = Error::success();
    StringMap<int> MemberCount;
    for (auto &Child : OldArchive->children(Err)) {
      int Pos = Ret.size();
      Expected<StringRef> NameOrErr = Child.getName();
      failIfError(NameOrErr.takeError());
      std::string Name = std::string(NameOrErr.get());
      if (comparePaths(Name, RelPos)) {
        assert(AddAfter || AddBefore);
        if (AddBefore)
          InsertPos = Pos;
        else
          InsertPos = Pos + 1;
      }

      std::vector<StringRef>::iterator MemberI = Members.end();
      InsertAction Action =
          computeInsertAction(Operation, Child, Name, MemberI, MemberCount);
      switch (Action) {
      case IA_AddOldMember:
        addChildMember(Ret, Child, /*FlattenArchive=*/Thin);
        break;
      case IA_AddNewMember:
        addMember(Ret, *MemberI);
        break;
      case IA_Delete:
        break;
      case IA_MoveOldMember:
        addChildMember(Moved, Child, /*FlattenArchive=*/Thin);
        break;
      case IA_MoveNewMember:
        addMember(Moved, *MemberI);
        break;
      }
      // When processing elements with the count param, we need to preserve the
      // full members list when iterating over all archive members. For
      // instance, "llvm-ar dN 2 archive.a member.o" should delete the second
      // file named member.o it sees; we are not done with member.o the first
      // time we see it in the archive.
      if (MemberI != Members.end() && !CountParam)
        Members.erase(MemberI);
    }
    failIfError(std::move(Err));
  }

  if (Operation == Delete)
    return Ret;

  if (!RelPos.empty() && InsertPos == -1)
    fail("insertion point not found");

  if (RelPos.empty())
    InsertPos = Ret.size();

  assert(unsigned(InsertPos) <= Ret.size());
  int Pos = InsertPos;
  for (auto &M : Moved) {
    Ret.insert(Ret.begin() + Pos, std::move(M));
    ++Pos;
  }

  if (AddLibrary) {
    assert(Operation == QuickAppend);
    for (auto &Member : Members)
      addMember(Ret, Member, /*FlattenArchive=*/true);
    return Ret;
  }

  std::vector<NewArchiveMember> NewMembers;
  for (auto &Member : Members)
    addMember(NewMembers, Member, /*FlattenArchive=*/Thin);
  Ret.reserve(Ret.size() + NewMembers.size());
  std::move(NewMembers.begin(), NewMembers.end(),
            std::inserter(Ret, std::next(Ret.begin(), InsertPos)));

  return Ret;
}

static object::Archive::Kind getDefaultForHost() {
  return Triple(sys::getProcessTriple()).isOSDarwin()
             ? object::Archive::K_DARWIN
             : object::Archive::K_GNU;
}

static object::Archive::Kind getKindFromMember(const NewArchiveMember &Member) {
  auto MemBufferRef = Member.Buf->getMemBufferRef();
  Expected<std::unique_ptr<object::ObjectFile>> OptionalObject =
      object::ObjectFile::createObjectFile(MemBufferRef);

  if (OptionalObject)
    return isa<object::MachOObjectFile>(**OptionalObject)
               ? object::Archive::K_DARWIN
               : object::Archive::K_GNU;

  // squelch the error in case we had a non-object file
  consumeError(OptionalObject.takeError());

  // If we're adding a bitcode file to the archive, detect the Archive kind
  // based on the target triple.
  LLVMContext Context;
  if (identify_magic(MemBufferRef.getBuffer()) == file_magic::bitcode) {
    if (auto ObjOrErr = object::SymbolicFile::createSymbolicFile(
            MemBufferRef, file_magic::bitcode, &Context)) {
      auto &IRObject = cast<object::IRObjectFile>(**ObjOrErr);
      return Triple(IRObject.getTargetTriple()).isOSDarwin()
                 ? object::Archive::K_DARWIN
                 : object::Archive::K_GNU;
    } else {
      // Squelch the error in case this was not a SymbolicFile.
      consumeError(ObjOrErr.takeError());
    }
  }

  return getDefaultForHost();
}

static void performWriteOperation(ArchiveOperation Operation,
                                  object::Archive *OldArchive,
                                  std::unique_ptr<MemoryBuffer> OldArchiveBuf,
                                  std::vector<NewArchiveMember> *NewMembersP) {
  std::vector<NewArchiveMember> NewMembers;
  if (!NewMembersP)
    NewMembers = computeNewArchiveMembers(Operation, OldArchive);

  object::Archive::Kind Kind;
  switch (FormatType) {
  case Default:
    if (Thin)
      Kind = object::Archive::K_GNU;
    else if (OldArchive)
      Kind = OldArchive->kind();
    else if (NewMembersP)
      Kind = !NewMembersP->empty() ? getKindFromMember(NewMembersP->front())
                                   : getDefaultForHost();
    else
      Kind = !NewMembers.empty() ? getKindFromMember(NewMembers.front())
                                 : getDefaultForHost();
    break;
  case GNU:
    Kind = object::Archive::K_GNU;
    break;
  case BSD:
    if (Thin)
      fail("only the gnu format has a thin mode");
    Kind = object::Archive::K_BSD;
    break;
  case DARWIN:
    if (Thin)
      fail("only the gnu format has a thin mode");
    Kind = object::Archive::K_DARWIN;
    break;
  case Unknown:
    llvm_unreachable("");
  }

  Error E =
      writeArchive(ArchiveName, NewMembersP ? *NewMembersP : NewMembers, Symtab,
                   Kind, Deterministic, Thin, std::move(OldArchiveBuf));
  failIfError(std::move(E), ArchiveName);
}

static void createSymbolTable(object::Archive *OldArchive) {
  // When an archive is created or modified, if the s option is given, the
  // resulting archive will have a current symbol table. If the S option
  // is given, it will have no symbol table.
  // In summary, we only need to update the symbol table if we have none.
  // This is actually very common because of broken build systems that think
  // they have to run ranlib.
  if (OldArchive->hasSymbolTable())
    return;

  performWriteOperation(CreateSymTab, OldArchive, nullptr, nullptr);
}

static void performOperation(ArchiveOperation Operation,
                             object::Archive *OldArchive,
                             std::unique_ptr<MemoryBuffer> OldArchiveBuf,
                             std::vector<NewArchiveMember> *NewMembers) {
  switch (Operation) {
  case Print:
  case DisplayTable:
  case Extract:
    performReadOperation(Operation, OldArchive);
    return;

  case Delete:
  case Move:
  case QuickAppend:
  case ReplaceOrInsert:
    performWriteOperation(Operation, OldArchive, std::move(OldArchiveBuf),
                          NewMembers);
    return;
  case CreateSymTab:
    createSymbolTable(OldArchive);
    return;
  }
  llvm_unreachable("Unknown operation.");
}

static int performOperation(ArchiveOperation Operation,
                            std::vector<NewArchiveMember> *NewMembers) {
  // Create or open the archive object.
  ErrorOr<std::unique_ptr<MemoryBuffer>> Buf =
      MemoryBuffer::getFile(ArchiveName, -1, false);
  std::error_code EC = Buf.getError();
  if (EC && EC != errc::no_such_file_or_directory)
    fail("unable to open '" + ArchiveName + "': " + EC.message());

  if (!EC) {
    Error Err = Error::success();
    object::Archive Archive(Buf.get()->getMemBufferRef(), Err);
    failIfError(std::move(Err), "unable to load '" + ArchiveName + "'");
    if (Archive.isThin())
      CompareFullPath = true;
    performOperation(Operation, &Archive, std::move(Buf.get()), NewMembers);
    return 0;
  }

  assert(EC == errc::no_such_file_or_directory);

  if (!shouldCreateArchive(Operation)) {
    failIfError(EC, Twine("unable to load '") + ArchiveName + "'");
  } else {
    if (!Create) {
      // Produce a warning if we should and we're creating the archive
      WithColor::warning(errs(), ToolName)
          << "creating " << ArchiveName << "\n";
    }
  }

  performOperation(Operation, nullptr, nullptr, NewMembers);
  return 0;
}

static void runMRIScript() {
  enum class MRICommand { AddLib, AddMod, Create, CreateThin, Delete, Save, End, Invalid };

  ErrorOr<std::unique_ptr<MemoryBuffer>> Buf = MemoryBuffer::getSTDIN();
  failIfError(Buf.getError());
  const MemoryBuffer &Ref = *Buf.get();
  bool Saved = false;
  std::vector<NewArchiveMember> NewMembers;
  ParsingMRIScript = true;

  for (line_iterator I(Ref, /*SkipBlanks*/ false), E; I != E; ++I) {
    ++MRILineNumber;
    StringRef Line = *I;
    Line = Line.split(';').first;
    Line = Line.split('*').first;
    Line = Line.trim();
    if (Line.empty())
      continue;
    StringRef CommandStr, Rest;
    std::tie(CommandStr, Rest) = Line.split(' ');
    Rest = Rest.trim();
    if (!Rest.empty() && Rest.front() == '"' && Rest.back() == '"')
      Rest = Rest.drop_front().drop_back();
    auto Command = StringSwitch<MRICommand>(CommandStr.lower())
                       .Case("addlib", MRICommand::AddLib)
                       .Case("addmod", MRICommand::AddMod)
                       .Case("create", MRICommand::Create)
                       .Case("createthin", MRICommand::CreateThin)
                       .Case("delete", MRICommand::Delete)
                       .Case("save", MRICommand::Save)
                       .Case("end", MRICommand::End)
                       .Default(MRICommand::Invalid);

    switch (Command) {
    case MRICommand::AddLib: {
      object::Archive &Lib = readLibrary(Rest);
      {
        Error Err = Error::success();
        for (auto &Member : Lib.children(Err))
          addChildMember(NewMembers, Member, /*FlattenArchive=*/Thin);
        failIfError(std::move(Err));
      }
      break;
    }
    case MRICommand::AddMod:
      addMember(NewMembers, Rest);
      break;
    case MRICommand::CreateThin:
      Thin = true;
      LLVM_FALLTHROUGH;
    case MRICommand::Create:
      Create = true;
      if (!ArchiveName.empty())
        fail("editing multiple archives not supported");
      if (Saved)
        fail("file already saved");
      ArchiveName = std::string(Rest);
      break;
    case MRICommand::Delete: {
      llvm::erase_if(NewMembers, [=](NewArchiveMember &M) {
        return comparePaths(M.MemberName, Rest);
      });
      break;
    }
    case MRICommand::Save:
      Saved = true;
      break;
    case MRICommand::End:
      break;
    case MRICommand::Invalid:
      fail("unknown command: " + CommandStr);
    }
  }

  ParsingMRIScript = false;

  // Nothing to do if not saved.
  if (Saved)
    performOperation(ReplaceOrInsert, &NewMembers);
  exit(0);
}

static bool handleGenericOption(StringRef arg) {
  if (arg == "-help" || arg == "--help" || arg == "-h") {
    printHelpMessage();
    return true;
  }
  if (arg == "-version" || arg == "--version") {
    cl::PrintVersionMessage();
    return true;
  }
  return false;
}

static const char *matchFlagWithArg(StringRef Expected,
                                    ArrayRef<const char *>::iterator &ArgIt,
                                    ArrayRef<const char *> Args) {
  StringRef Arg = *ArgIt;

  if (Arg.startswith("--"))
    Arg = Arg.substr(2);
  else if (Arg.startswith("-"))
    Arg = Arg.substr(1);

  size_t len = Expected.size();
  if (Arg == Expected) {
    if (++ArgIt == Args.end())
      fail(std::string(Expected) + " requires an argument");

    return *ArgIt;
  }
  if (Arg.startswith(Expected) && Arg.size() > len && Arg[len] == '=')
    return Arg.data() + len + 1;

  return nullptr;
}

static cl::TokenizerCallback getRspQuoting(ArrayRef<const char *> ArgsArr) {
  cl::TokenizerCallback Ret =
      Triple(sys::getProcessTriple()).getOS() == Triple::Win32
          ? cl::TokenizeWindowsCommandLine
          : cl::TokenizeGNUCommandLine;

  for (ArrayRef<const char *>::iterator ArgIt = ArgsArr.begin();
       ArgIt != ArgsArr.end(); ++ArgIt) {
    if (const char *Match = matchFlagWithArg("rsp-quoting", ArgIt, ArgsArr)) {
      StringRef MatchRef = Match;
      if (MatchRef == "posix")
        Ret = cl::TokenizeGNUCommandLine;
      else if (MatchRef == "windows")
        Ret = cl::TokenizeWindowsCommandLine;
      else
        fail(std::string("Invalid response file quoting style ") + Match);
    }
  }

  return Ret;
}

static int ar_main(int argc, char **argv) {
  SmallVector<const char *, 0> Argv(argv + 1, argv + argc);
  StringSaver Saver(Alloc);

  cl::ExpandResponseFiles(Saver, getRspQuoting(makeArrayRef(argv, argc)), Argv);

  for (ArrayRef<const char *>::iterator ArgIt = Argv.begin();
       ArgIt != Argv.end(); ++ArgIt) {
    const char *Match = nullptr;

    if (handleGenericOption(*ArgIt))
      return 0;
    if (strcmp(*ArgIt, "--") == 0) {
      ++ArgIt;
      for (; ArgIt != Argv.end(); ++ArgIt)
        PositionalArgs.push_back(*ArgIt);
      break;
    }

    if (*ArgIt[0] != '-') {
      if (Options.empty())
        Options += *ArgIt;
      else
        PositionalArgs.push_back(*ArgIt);
      continue;
    }

    if (strcmp(*ArgIt, "-M") == 0) {
      MRI = true;
      continue;
    }

    Match = matchFlagWithArg("format", ArgIt, Argv);
    if (Match) {
      FormatType = StringSwitch<Format>(Match)
                       .Case("default", Default)
                       .Case("gnu", GNU)
                       .Case("darwin", DARWIN)
                       .Case("bsd", BSD)
                       .Default(Unknown);
      if (FormatType == Unknown)
        fail(std::string("Invalid format ") + Match);
      continue;
    }

    if (matchFlagWithArg("plugin", ArgIt, Argv) ||
        matchFlagWithArg("rsp-quoting", ArgIt, Argv))
      continue;

    Options += *ArgIt + 1;
  }

  ArchiveOperation Operation = parseCommandLine();
  return performOperation(Operation, nullptr);
}

static int ranlib_main(int argc, char **argv) {
  bool ArchiveSpecified = false;
  for (int i = 1; i < argc; ++i) {
    StringRef arg(argv[i]);
    if (handleGenericOption(arg)) {
      return 0;
    } else if (arg.consume_front("-")) {
      // Handle the -D/-U flag
      while (!arg.empty()) {
        if (arg.front() == 'D') {
          Deterministic = true;
        } else if (arg.front() == 'U') {
          Deterministic = false;
        } else if (arg.front() == 'h') {
          printHelpMessage();
          return 0;
        } else if (arg.front() == 'v') {
          cl::PrintVersionMessage();
          return 0;
        } else {
          // TODO: GNU ranlib also supports a -t flag
          fail("Invalid option: '-" + arg + "'");
        }
        arg = arg.drop_front(1);
      }
    } else {
      if (ArchiveSpecified)
        fail("exactly one archive should be specified");
      ArchiveSpecified = true;
      ArchiveName = arg.str();
    }
  }
  if (!ArchiveSpecified) {
    badUsage("an archive name must be specified");
  }
  return performOperation(CreateSymTab, nullptr);
}

extern "C" int ZigLlvmAr_main(int argc, char **argv);
int ZigLlvmAr_main(int argc, char **argv) {
  // ZIG MOD: On windows, InitLLVM calls GetCommandLineW(),
  // and overwrites the args.  We don't want it to do that,
  // and we also don't need the signal handlers it installs
  // (we have our own already), so we just use llvm_shutdown_obj
  // instead.
  // InitLLVM X(argc, argv);
  llvm::llvm_shutdown_obj X;

  ToolName = argv[0];

  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmParsers();

  Stem = sys::path::stem(ToolName);
  auto Is = [](StringRef Tool) {
    // We need to recognize the following filenames.
    //
    // Lib.exe -> lib (see D44808, MSBuild runs Lib.exe)
    // dlltool.exe -> dlltool
    // arm-pokymllib32-linux-gnueabi-llvm-ar-10 -> ar
    auto I = Stem.rfind_insensitive(Tool);
    return I != StringRef::npos &&
           (I + Tool.size() == Stem.size() || !isAlnum(Stem[I + Tool.size()]));
  };

  if (Is("dlltool"))
    return dlltoolDriverMain(makeArrayRef(argv, argc));
  if (Is("ranlib"))
    return ranlib_main(argc, argv);
  if (Is("lib"))
    return libDriverMain(makeArrayRef(argv, argc));
  if (Is("ar"))
    return ar_main(argc, argv);

  fail("not ranlib, ar, lib or dlltool");
}
