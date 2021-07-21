# Copyright (c) 2016 Andrew Kelley
# This file is MIT licensed.
# See http://opensource.org/licenses/MIT

# CLANG_FOUND
# CLANG_INCLUDE_DIRS
# CLANG_LIBRARIES
# CLANG_LIBDIRS

find_path(CLANG_INCLUDE_DIRS NAMES clang/Frontend/ASTUnit.h
  PATHS
    /usr/lib/llvm/12/include
    /usr/lib/llvm-12/include
    /usr/lib/llvm-12.0/include
    /usr/local/llvm120/include
    /usr/local/llvm12/include
    /usr/local/opt/llvm@12/include
    /opt/homebrew/opt/llvm@12/include
    /mingw64/include
)

if(ZIG_PREFER_CLANG_CPP_DYLIB)
  find_library(CLANG_LIBRARIES
    NAMES
      clang-cpp-12.0
      clang-cpp120
      clang-cpp
    PATHS
      ${CLANG_LIBDIRS}
      /usr/lib/llvm/12/lib
      /usr/lib/llvm/12/lib64
      /usr/lib/llvm-12/lib
      /usr/local/llvm120/lib
      /usr/local/llvm12/lib
      /usr/local/opt/llvm@12/lib
      /opt/homebrew/opt/llvm@12/lib
  )
endif()

if(NOT CLANG_LIBRARIES)
  macro(FIND_AND_ADD_CLANG_LIB _libname_)
    string(TOUPPER ${_libname_} _prettylibname_)
    find_library(CLANG_${_prettylibname_}_LIB NAMES ${_libname_}
      PATHS
        ${CLANG_LIBDIRS}
        /usr/lib/llvm/12/lib
        /usr/lib/llvm-12/lib
        /usr/lib/llvm-12.0/lib
        /usr/local/llvm120/lib
        /usr/local/llvm12/lib
        /usr/local/opt/llvm@12/lib
        /opt/homebrew/opt/llvm@12/lib
        /mingw64/lib
        /c/msys64/mingw64/lib
        c:\\msys64\\mingw64\\lib
    )
    if(CLANG_${_prettylibname_}_LIB)
      set(CLANG_LIBRARIES ${CLANG_LIBRARIES} ${CLANG_${_prettylibname_}_LIB})
    endif()
  endmacro(FIND_AND_ADD_CLANG_LIB)

  FIND_AND_ADD_CLANG_LIB(clangFrontendTool)
  FIND_AND_ADD_CLANG_LIB(clangCodeGen)
  FIND_AND_ADD_CLANG_LIB(clangFrontend)
  FIND_AND_ADD_CLANG_LIB(clangDriver)
  FIND_AND_ADD_CLANG_LIB(clangSerialization)
  FIND_AND_ADD_CLANG_LIB(clangSema)
  FIND_AND_ADD_CLANG_LIB(clangStaticAnalyzerFrontend)
  FIND_AND_ADD_CLANG_LIB(clangStaticAnalyzerCheckers)
  FIND_AND_ADD_CLANG_LIB(clangStaticAnalyzerCore)
  FIND_AND_ADD_CLANG_LIB(clangAnalysis)
  FIND_AND_ADD_CLANG_LIB(clangASTMatchers)
  FIND_AND_ADD_CLANG_LIB(clangAST)
  FIND_AND_ADD_CLANG_LIB(clangParse)
  FIND_AND_ADD_CLANG_LIB(clangSema)
  FIND_AND_ADD_CLANG_LIB(clangBasic)
  FIND_AND_ADD_CLANG_LIB(clangEdit)
  FIND_AND_ADD_CLANG_LIB(clangLex)
  FIND_AND_ADD_CLANG_LIB(clangARCMigrate)
  FIND_AND_ADD_CLANG_LIB(clangRewriteFrontend)
  FIND_AND_ADD_CLANG_LIB(clangRewrite)
  FIND_AND_ADD_CLANG_LIB(clangCrossTU)
  FIND_AND_ADD_CLANG_LIB(clangIndex)
  FIND_AND_ADD_CLANG_LIB(clangToolingCore)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(clang DEFAULT_MSG CLANG_LIBRARIES CLANG_INCLUDE_DIRS)

mark_as_advanced(CLANG_INCLUDE_DIRS CLANG_LIBRARIES CLANG_LIBDIRS)
