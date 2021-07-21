# Copyright (c) 2014 Andrew Kelley
# This file is MIT licensed.
# See http://opensource.org/licenses/MIT

# LLVM_FOUND
# LLVM_INCLUDE_DIRS
# LLVM_LIBRARIES
# LLVM_LIBDIRS

find_path(LLVM_INCLUDE_DIRS NAMES llvm/IR/IRBuilder.h
  PATHS
    /usr/lib/llvm/12/include
    /usr/lib/llvm-12/include
    /usr/lib/llvm-12.0/include
    /usr/local/llvm12/include
    /usr/local/llvm120/include
    /usr/local/opt/llvm@12/include
    /opt/homebrew/opt/llvm@12/include
    /mingw64/include
)

if(ZIG_PREFER_CLANG_CPP_DYLIB)
  find_library(LLVM_LIBRARIES
    NAMES
      LLVM-12.0
      LLVM-12
      LLVM-120
      LLVM
    PATHS
      ${LLVM_LIBDIRS}
      /usr/lib/llvm/12/lib
      /usr/lib/llvm/12/lib64
      /usr/lib/llvm-12/lib
      /usr/local/llvm12/lib
      /usr/local/llvm120/lib
      /usr/local/opt/llvm@12/lib
      /opt/homebrew/opt/llvm@12/lib
  )

  find_program(LLVM_CONFIG_EXE
      NAMES llvm-config-12 llvm-config-12.0 llvm-config120 llvm-config12 llvm-config
      PATHS
          "/mingw64/bin"
          "/c/msys64/mingw64/bin"
          "c:/msys64/mingw64/bin"
          "C:/Libraries/llvm-12.0.0/bin")

  if ("${LLVM_CONFIG_EXE}" STREQUAL "LLVM_CONFIG_EXE-NOTFOUND")
    message(FATAL_ERROR "unable to find llvm-config")
  endif()

  if ("${LLVM_CONFIG_EXE}" STREQUAL "LLVM_CONFIG_EXE-NOTFOUND")
    message(FATAL_ERROR "unable to find llvm-config")
  endif()

  execute_process(
    COMMAND ${LLVM_CONFIG_EXE} --version
    OUTPUT_VARIABLE LLVM_CONFIG_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE)

  if("${LLVM_CONFIG_VERSION}" VERSION_LESS 12)
    message(FATAL_ERROR "expected LLVM 12.x but found ${LLVM_CONFIG_VERSION} using ${LLVM_CONFIG_EXE}")
  endif()
  if("${LLVM_CONFIG_VERSION}" VERSION_EQUAL 13)
    message(FATAL_ERROR "expected LLVM 12.x but found ${LLVM_CONFIG_VERSION} using ${LLVM_CONFIG_EXE}")
  endif()
  if("${LLVM_CONFIG_VERSION}" VERSION_GREATER 13)
    message(FATAL_ERROR "expected LLVM 12.x but found ${LLVM_CONFIG_VERSION} using ${LLVM_CONFIG_EXE}")
  endif()
elseif(ZIG_USE_LLVM_CONFIG)
  find_program(LLVM_CONFIG_EXE
      NAMES llvm-config-12 llvm-config-12.0 llvm-config120 llvm-config12 llvm-config
      PATHS
          "/mingw64/bin"
          "/c/msys64/mingw64/bin"
          "c:/msys64/mingw64/bin"
          "C:/Libraries/llvm-12.0.0/bin")

  if ("${LLVM_CONFIG_EXE}" STREQUAL "LLVM_CONFIG_EXE-NOTFOUND")
    message(FATAL_ERROR "unable to find llvm-config")
  endif()

  if ("${LLVM_CONFIG_EXE}" STREQUAL "LLVM_CONFIG_EXE-NOTFOUND")
    message(FATAL_ERROR "unable to find llvm-config")
  endif()

  execute_process(
    COMMAND ${LLVM_CONFIG_EXE} --version
    OUTPUT_VARIABLE LLVM_CONFIG_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE)

  if("${LLVM_CONFIG_VERSION}" VERSION_LESS 12)
    message(FATAL_ERROR "expected LLVM 12.x but found ${LLVM_CONFIG_VERSION} using ${LLVM_CONFIG_EXE}")
  endif()
  if("${LLVM_CONFIG_VERSION}" VERSION_EQUAL 13)
    message(FATAL_ERROR "expected LLVM 12.x but found ${LLVM_CONFIG_VERSION} using ${LLVM_CONFIG_EXE}")
  endif()
  if("${LLVM_CONFIG_VERSION}" VERSION_GREATER 13)
    message(FATAL_ERROR "expected LLVM 12.x but found ${LLVM_CONFIG_VERSION} using ${LLVM_CONFIG_EXE}")
  endif()

  execute_process(
    COMMAND ${LLVM_CONFIG_EXE} --targets-built
      OUTPUT_VARIABLE LLVM_TARGETS_BUILT_SPACES
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  string(REPLACE " " ";" LLVM_TARGETS_BUILT "${LLVM_TARGETS_BUILT_SPACES}")
  function(NEED_TARGET TARGET_NAME)
      list (FIND LLVM_TARGETS_BUILT "${TARGET_NAME}" _index)
      if (${_index} EQUAL -1)
          message(FATAL_ERROR "LLVM (according to ${LLVM_CONFIG_EXE}) is missing target ${TARGET_NAME}. Zig requires LLVM to be built with all default targets enabled.")
      endif()
  endfunction(NEED_TARGET)
  NEED_TARGET("AArch64")
  NEED_TARGET("AMDGPU")
  NEED_TARGET("ARM")
  NEED_TARGET("AVR")
  NEED_TARGET("BPF")
  NEED_TARGET("Hexagon")
  NEED_TARGET("Lanai")
  NEED_TARGET("Mips")
  NEED_TARGET("MSP430")
  NEED_TARGET("NVPTX")
  NEED_TARGET("PowerPC")
  NEED_TARGET("RISCV")
  NEED_TARGET("Sparc")
  NEED_TARGET("SystemZ")
  NEED_TARGET("WebAssembly")
  NEED_TARGET("X86")
  NEED_TARGET("XCore")

  if(ZIG_STATIC_LLVM)
    execute_process(
        COMMAND ${LLVM_CONFIG_EXE} --libfiles --link-static
        OUTPUT_VARIABLE LLVM_LIBRARIES_SPACES
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(REPLACE " " ";" LLVM_LIBRARIES "${LLVM_LIBRARIES_SPACES}")

    execute_process(
        COMMAND ${LLVM_CONFIG_EXE} --system-libs --link-static
        OUTPUT_VARIABLE LLVM_SYSTEM_LIBS_SPACES
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(REPLACE " " ";" LLVM_SYSTEM_LIBS "${LLVM_SYSTEM_LIBS_SPACES}")

    execute_process(
        COMMAND ${LLVM_CONFIG_EXE} --libdir --link-static
        OUTPUT_VARIABLE LLVM_LIBDIRS_SPACES
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(REPLACE " " ";" LLVM_LIBDIRS "${LLVM_LIBDIRS_SPACES}")
  endif()
  if(NOT LLVM_LIBRARIES)
    execute_process(
        COMMAND ${LLVM_CONFIG_EXE} --libs
        OUTPUT_VARIABLE LLVM_LIBRARIES_SPACES
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(REPLACE " " ";" LLVM_LIBRARIES "${LLVM_LIBRARIES_SPACES}")

    execute_process(
        COMMAND ${LLVM_CONFIG_EXE} --system-libs
        OUTPUT_VARIABLE LLVM_SYSTEM_LIBS_SPACES
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(REPLACE " " ";" LLVM_SYSTEM_LIBS "${LLVM_SYSTEM_LIBS_SPACES}")

    execute_process(
        COMMAND ${LLVM_CONFIG_EXE} --libdir
        OUTPUT_VARIABLE LLVM_LIBDIRS_SPACES
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(REPLACE " " ";" LLVM_LIBDIRS "${LLVM_LIBDIRS_SPACES}")
  endif()

  set(LLVM_LIBRARIES ${LLVM_LIBRARIES} ${LLVM_SYSTEM_LIBS})

  if(NOT LLVM_LIBRARIES)
    find_library(LLVM_LIBRARIES NAMES LLVM LLVM-12 LLVM-12.0)
  endif()

  link_directories("${CMAKE_PREFIX_PATH}/lib")
  link_directories("${LLVM_LIBDIRS}")
else()
  # Here we assume that we're cross compiling with Zig, of course. No reason
  # to support more complicated setups.

  macro(FIND_AND_ADD_LLVM_LIB _libname_)
    string(TOUPPER ${_libname_} _prettylibname_)
    find_library(LLVM_${_prettylibname_}_LIB NAMES ${_libname_}
      PATHS
      ${LLVM_LIBDIRS}
      /usr/lib/llvm/12/lib
      /usr/lib/llvm-12/lib
      /usr/lib/llvm-12.0/lib
      /usr/local/llvm120/lib
      /usr/local/llvm12/lib
      /usr/local/opt/llvm@12/lib
      /opt/homebrew/opt/llvm@12/lib
      /mingw64/lib
      /c/msys64/mingw64/lib
      c:\\msys64\\mingw64\\lib)
    set(LLVM_LIBRARIES ${LLVM_LIBRARIES} ${LLVM_${_prettylibname_}_LIB})
  endmacro(FIND_AND_ADD_LLVM_LIB)

  # This list can be re-generated with `llvm-config --libfiles` and then
  # reformatting using your favorite text editor. Note we do not execute
  # `llvm-config` here because we are cross compiling.
  FIND_AND_ADD_LLVM_LIB(LLVMWindowsManifest)
  FIND_AND_ADD_LLVM_LIB(LLVMXRay)
  FIND_AND_ADD_LLVM_LIB(LLVMLibDriver)
  FIND_AND_ADD_LLVM_LIB(LLVMDlltoolDriver)
  FIND_AND_ADD_LLVM_LIB(LLVMCoverage)
  FIND_AND_ADD_LLVM_LIB(LLVMLineEditor)
  FIND_AND_ADD_LLVM_LIB(LLVMXCoreDisassembler)
  FIND_AND_ADD_LLVM_LIB(LLVMXCoreCodeGen)
  FIND_AND_ADD_LLVM_LIB(LLVMXCoreDesc)
  FIND_AND_ADD_LLVM_LIB(LLVMXCoreInfo)
  FIND_AND_ADD_LLVM_LIB(LLVMX86Disassembler)
  FIND_AND_ADD_LLVM_LIB(LLVMX86AsmParser)
  FIND_AND_ADD_LLVM_LIB(LLVMX86CodeGen)
  FIND_AND_ADD_LLVM_LIB(LLVMX86Desc)
  FIND_AND_ADD_LLVM_LIB(LLVMX86Info)
  FIND_AND_ADD_LLVM_LIB(LLVMWebAssemblyDisassembler)
  FIND_AND_ADD_LLVM_LIB(LLVMWebAssemblyAsmParser)
  FIND_AND_ADD_LLVM_LIB(LLVMWebAssemblyCodeGen)
  FIND_AND_ADD_LLVM_LIB(LLVMWebAssemblyDesc)
  FIND_AND_ADD_LLVM_LIB(LLVMWebAssemblyInfo)
  FIND_AND_ADD_LLVM_LIB(LLVMSystemZDisassembler)
  FIND_AND_ADD_LLVM_LIB(LLVMSystemZAsmParser)
  FIND_AND_ADD_LLVM_LIB(LLVMSystemZCodeGen)
  FIND_AND_ADD_LLVM_LIB(LLVMSystemZDesc)
  FIND_AND_ADD_LLVM_LIB(LLVMSystemZInfo)
  FIND_AND_ADD_LLVM_LIB(LLVMSparcDisassembler)
  FIND_AND_ADD_LLVM_LIB(LLVMSparcAsmParser)
  FIND_AND_ADD_LLVM_LIB(LLVMSparcCodeGen)
  FIND_AND_ADD_LLVM_LIB(LLVMSparcDesc)
  FIND_AND_ADD_LLVM_LIB(LLVMSparcInfo)
  FIND_AND_ADD_LLVM_LIB(LLVMRISCVDisassembler)
  FIND_AND_ADD_LLVM_LIB(LLVMRISCVAsmParser)
  FIND_AND_ADD_LLVM_LIB(LLVMRISCVCodeGen)
  FIND_AND_ADD_LLVM_LIB(LLVMRISCVDesc)
  FIND_AND_ADD_LLVM_LIB(LLVMRISCVInfo)
  FIND_AND_ADD_LLVM_LIB(LLVMPowerPCDisassembler)
  FIND_AND_ADD_LLVM_LIB(LLVMPowerPCAsmParser)
  FIND_AND_ADD_LLVM_LIB(LLVMPowerPCCodeGen)
  FIND_AND_ADD_LLVM_LIB(LLVMPowerPCDesc)
  FIND_AND_ADD_LLVM_LIB(LLVMPowerPCInfo)
  FIND_AND_ADD_LLVM_LIB(LLVMNVPTXCodeGen)
  FIND_AND_ADD_LLVM_LIB(LLVMNVPTXDesc)
  FIND_AND_ADD_LLVM_LIB(LLVMNVPTXInfo)
  FIND_AND_ADD_LLVM_LIB(LLVMMSP430Disassembler)
  FIND_AND_ADD_LLVM_LIB(LLVMMSP430AsmParser)
  FIND_AND_ADD_LLVM_LIB(LLVMMSP430CodeGen)
  FIND_AND_ADD_LLVM_LIB(LLVMMSP430Desc)
  FIND_AND_ADD_LLVM_LIB(LLVMMSP430Info)
  FIND_AND_ADD_LLVM_LIB(LLVMMipsDisassembler)
  FIND_AND_ADD_LLVM_LIB(LLVMMipsAsmParser)
  FIND_AND_ADD_LLVM_LIB(LLVMMipsCodeGen)
  FIND_AND_ADD_LLVM_LIB(LLVMMipsDesc)
  FIND_AND_ADD_LLVM_LIB(LLVMMipsInfo)
  FIND_AND_ADD_LLVM_LIB(LLVMLanaiDisassembler)
  FIND_AND_ADD_LLVM_LIB(LLVMLanaiCodeGen)
  FIND_AND_ADD_LLVM_LIB(LLVMLanaiAsmParser)
  FIND_AND_ADD_LLVM_LIB(LLVMLanaiDesc)
  FIND_AND_ADD_LLVM_LIB(LLVMLanaiInfo)
  FIND_AND_ADD_LLVM_LIB(LLVMHexagonDisassembler)
  FIND_AND_ADD_LLVM_LIB(LLVMHexagonCodeGen)
  FIND_AND_ADD_LLVM_LIB(LLVMHexagonAsmParser)
  FIND_AND_ADD_LLVM_LIB(LLVMHexagonDesc)
  FIND_AND_ADD_LLVM_LIB(LLVMHexagonInfo)
  FIND_AND_ADD_LLVM_LIB(LLVMBPFDisassembler)
  FIND_AND_ADD_LLVM_LIB(LLVMBPFAsmParser)
  FIND_AND_ADD_LLVM_LIB(LLVMBPFCodeGen)
  FIND_AND_ADD_LLVM_LIB(LLVMBPFDesc)
  FIND_AND_ADD_LLVM_LIB(LLVMBPFInfo)
  FIND_AND_ADD_LLVM_LIB(LLVMAVRDisassembler)
  FIND_AND_ADD_LLVM_LIB(LLVMAVRAsmParser)
  FIND_AND_ADD_LLVM_LIB(LLVMAVRCodeGen)
  FIND_AND_ADD_LLVM_LIB(LLVMAVRDesc)
  FIND_AND_ADD_LLVM_LIB(LLVMAVRInfo)
  FIND_AND_ADD_LLVM_LIB(LLVMARMDisassembler)
  FIND_AND_ADD_LLVM_LIB(LLVMARMAsmParser)
  FIND_AND_ADD_LLVM_LIB(LLVMARMCodeGen)
  FIND_AND_ADD_LLVM_LIB(LLVMARMDesc)
  FIND_AND_ADD_LLVM_LIB(LLVMARMUtils)
  FIND_AND_ADD_LLVM_LIB(LLVMARMInfo)
  FIND_AND_ADD_LLVM_LIB(LLVMAMDGPUDisassembler)
  FIND_AND_ADD_LLVM_LIB(LLVMAMDGPUAsmParser)
  FIND_AND_ADD_LLVM_LIB(LLVMAMDGPUCodeGen)
  FIND_AND_ADD_LLVM_LIB(LLVMAMDGPUDesc)
  FIND_AND_ADD_LLVM_LIB(LLVMAMDGPUUtils)
  FIND_AND_ADD_LLVM_LIB(LLVMAMDGPUInfo)
  FIND_AND_ADD_LLVM_LIB(LLVMAArch64Disassembler)
  FIND_AND_ADD_LLVM_LIB(LLVMAArch64AsmParser)
  FIND_AND_ADD_LLVM_LIB(LLVMAArch64CodeGen)
  FIND_AND_ADD_LLVM_LIB(LLVMAArch64Desc)
  FIND_AND_ADD_LLVM_LIB(LLVMAArch64Utils)
  FIND_AND_ADD_LLVM_LIB(LLVMAArch64Info)
  FIND_AND_ADD_LLVM_LIB(LLVMOrcJIT)
  FIND_AND_ADD_LLVM_LIB(LLVMMCJIT)
  FIND_AND_ADD_LLVM_LIB(LLVMJITLink)
  FIND_AND_ADD_LLVM_LIB(LLVMOrcTargetProcess)
  FIND_AND_ADD_LLVM_LIB(LLVMOrcShared)
  FIND_AND_ADD_LLVM_LIB(LLVMInterpreter)
  FIND_AND_ADD_LLVM_LIB(LLVMExecutionEngine)
  FIND_AND_ADD_LLVM_LIB(LLVMRuntimeDyld)
  FIND_AND_ADD_LLVM_LIB(LLVMSymbolize)
  FIND_AND_ADD_LLVM_LIB(LLVMDebugInfoPDB)
  FIND_AND_ADD_LLVM_LIB(LLVMDebugInfoGSYM)
  FIND_AND_ADD_LLVM_LIB(LLVMOption)
  FIND_AND_ADD_LLVM_LIB(LLVMObjectYAML)
  FIND_AND_ADD_LLVM_LIB(LLVMMCA)
  FIND_AND_ADD_LLVM_LIB(LLVMMCDisassembler)
  FIND_AND_ADD_LLVM_LIB(LLVMLTO)
  FIND_AND_ADD_LLVM_LIB(LLVMPasses)
  FIND_AND_ADD_LLVM_LIB(LLVMCFGuard)
  FIND_AND_ADD_LLVM_LIB(LLVMCoroutines)
  FIND_AND_ADD_LLVM_LIB(LLVMObjCARCOpts)
  FIND_AND_ADD_LLVM_LIB(LLVMHelloNew)
  FIND_AND_ADD_LLVM_LIB(LLVMipo)
  FIND_AND_ADD_LLVM_LIB(LLVMVectorize)
  FIND_AND_ADD_LLVM_LIB(LLVMLinker)
  FIND_AND_ADD_LLVM_LIB(LLVMInstrumentation)
  FIND_AND_ADD_LLVM_LIB(LLVMFrontendOpenMP)
  FIND_AND_ADD_LLVM_LIB(LLVMFrontendOpenACC)
  FIND_AND_ADD_LLVM_LIB(LLVMExtensions)
  FIND_AND_ADD_LLVM_LIB(LLVMDWARFLinker)
  FIND_AND_ADD_LLVM_LIB(LLVMGlobalISel)
  FIND_AND_ADD_LLVM_LIB(LLVMMIRParser)
  FIND_AND_ADD_LLVM_LIB(LLVMAsmPrinter)
  FIND_AND_ADD_LLVM_LIB(LLVMDebugInfoDWARF)
  FIND_AND_ADD_LLVM_LIB(LLVMSelectionDAG)
  FIND_AND_ADD_LLVM_LIB(LLVMCodeGen)
  FIND_AND_ADD_LLVM_LIB(LLVMIRReader)
  FIND_AND_ADD_LLVM_LIB(LLVMAsmParser)
  FIND_AND_ADD_LLVM_LIB(LLVMInterfaceStub)
  FIND_AND_ADD_LLVM_LIB(LLVMFileCheck)
  FIND_AND_ADD_LLVM_LIB(LLVMFuzzMutate)
  FIND_AND_ADD_LLVM_LIB(LLVMTarget)
  FIND_AND_ADD_LLVM_LIB(LLVMScalarOpts)
  FIND_AND_ADD_LLVM_LIB(LLVMInstCombine)
  FIND_AND_ADD_LLVM_LIB(LLVMAggressiveInstCombine)
  FIND_AND_ADD_LLVM_LIB(LLVMTransformUtils)
  FIND_AND_ADD_LLVM_LIB(LLVMBitWriter)
  FIND_AND_ADD_LLVM_LIB(LLVMAnalysis)
  FIND_AND_ADD_LLVM_LIB(LLVMProfileData)
  FIND_AND_ADD_LLVM_LIB(LLVMObject)
  FIND_AND_ADD_LLVM_LIB(LLVMTextAPI)
  FIND_AND_ADD_LLVM_LIB(LLVMMCParser)
  FIND_AND_ADD_LLVM_LIB(LLVMMC)
  FIND_AND_ADD_LLVM_LIB(LLVMDebugInfoCodeView)
  FIND_AND_ADD_LLVM_LIB(LLVMDebugInfoMSF)
  FIND_AND_ADD_LLVM_LIB(LLVMBitReader)
  FIND_AND_ADD_LLVM_LIB(LLVMCore)
  FIND_AND_ADD_LLVM_LIB(LLVMRemarks)
  FIND_AND_ADD_LLVM_LIB(LLVMBitstreamReader)
  FIND_AND_ADD_LLVM_LIB(LLVMBinaryFormat)
  FIND_AND_ADD_LLVM_LIB(LLVMSupport)
  FIND_AND_ADD_LLVM_LIB(LLVMDemangle)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(llvm DEFAULT_MSG LLVM_LIBRARIES LLVM_INCLUDE_DIRS)

mark_as_advanced(LLVM_INCLUDE_DIRS LLVM_LIBRARIES LLVM_LIBDIRS)
