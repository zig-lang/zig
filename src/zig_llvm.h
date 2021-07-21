/*
 * Copyright (c) 2015 Andrew Kelley
 *
 * This file is part of zig, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

#ifndef ZIG_ZIG_LLVM_HPP
#define ZIG_ZIG_LLVM_HPP

#include <stdbool.h>
#include <stddef.h>
#include <llvm-c/Core.h>
#include <llvm-c/Analysis.h>
#include <llvm-c/Target.h>
#include <llvm-c/Initialization.h>
#include <llvm-c/TargetMachine.h>

#ifdef __cplusplus
#define ZIG_EXTERN_C extern "C"
#else
#define ZIG_EXTERN_C
#endif

// ATTENTION: If you modify this file, be sure to update the corresponding
// extern function declarations in the self-hosted compiler.

struct ZigLLVMDIType;
struct ZigLLVMDIBuilder;
struct ZigLLVMDICompileUnit;
struct ZigLLVMDIScope;
struct ZigLLVMDIFile;
struct ZigLLVMDILexicalBlock;
struct ZigLLVMDISubprogram;
struct ZigLLVMDISubroutineType;
struct ZigLLVMDILocalVariable;
struct ZigLLVMDIGlobalVariable;
struct ZigLLVMDILocation;
struct ZigLLVMDIEnumerator;
struct ZigLLVMInsertionPoint;

ZIG_EXTERN_C void ZigLLVMInitializeLoopStrengthReducePass(LLVMPassRegistryRef R);
ZIG_EXTERN_C void ZigLLVMInitializeLowerIntrinsicsPass(LLVMPassRegistryRef R);

/// Caller must free memory with LLVMDisposeMessage
ZIG_EXTERN_C char *ZigLLVMGetHostCPUName(void);
ZIG_EXTERN_C char *ZigLLVMGetNativeFeatures(void);

ZIG_EXTERN_C bool ZigLLVMTargetMachineEmitToFile(LLVMTargetMachineRef targ_machine_ref, LLVMModuleRef module_ref,
        char **error_message, bool is_debug,
        bool is_small, bool time_report, bool tsan, bool lto,
        const char *asm_filename, const char *bin_filename, const char *llvm_ir_filename);


enum ZigLLVMABIType {
    ZigLLVMABITypeDefault, // Target-specific (either soft or hard depending on triple, etc).
    ZigLLVMABITypeSoft,    // Soft float.
    ZigLLVMABITypeHard     // Hard float.
};

ZIG_EXTERN_C LLVMTargetMachineRef ZigLLVMCreateTargetMachine(LLVMTargetRef T, const char *Triple,
    const char *CPU, const char *Features, LLVMCodeGenOptLevel Level, LLVMRelocMode Reloc,
    LLVMCodeModel CodeModel, bool function_sections, enum ZigLLVMABIType float_abi, const char *abi_name);

ZIG_EXTERN_C LLVMTypeRef ZigLLVMTokenTypeInContext(LLVMContextRef context_ref);

enum ZigLLVM_CallingConv {
    ZigLLVM_C = 0,
    ZigLLVM_Fast = 8,
    ZigLLVM_Cold = 9,
    ZigLLVM_GHC = 10,
    ZigLLVM_HiPE = 11,
    ZigLLVM_WebKit_JS = 12,
    ZigLLVM_AnyReg = 13,
    ZigLLVM_PreserveMost = 14,
    ZigLLVM_PreserveAll = 15,
    ZigLLVM_Swift = 16,
    ZigLLVM_CXX_FAST_TLS = 17,
    ZigLLVM_FirstTargetCC = 64,
    ZigLLVM_X86_StdCall = 64,
    ZigLLVM_X86_FastCall = 65,
    ZigLLVM_ARM_APCS = 66,
    ZigLLVM_ARM_AAPCS = 67,
    ZigLLVM_ARM_AAPCS_VFP = 68,
    ZigLLVM_MSP430_INTR = 69,
    ZigLLVM_X86_ThisCall = 70,
    ZigLLVM_PTX_Kernel = 71,
    ZigLLVM_PTX_Device = 72,
    ZigLLVM_SPIR_FUNC = 75,
    ZigLLVM_SPIR_KERNEL = 76,
    ZigLLVM_Intel_OCL_BI = 77,
    ZigLLVM_X86_64_SysV = 78,
    ZigLLVM_Win64 = 79,
    ZigLLVM_X86_VectorCall = 80,
    ZigLLVM_HHVM = 81,
    ZigLLVM_HHVM_C = 82,
    ZigLLVM_X86_INTR = 83,
    ZigLLVM_AVR_INTR = 84,
    ZigLLVM_AVR_SIGNAL = 85,
    ZigLLVM_AVR_BUILTIN = 86,
    ZigLLVM_AMDGPU_VS = 87,
    ZigLLVM_AMDGPU_GS = 88,
    ZigLLVM_AMDGPU_PS = 89,
    ZigLLVM_AMDGPU_CS = 90,
    ZigLLVM_AMDGPU_KERNEL = 91,
    ZigLLVM_X86_RegCall = 92,
    ZigLLVM_AMDGPU_HS = 93,
    ZigLLVM_MSP430_BUILTIN = 94,
    ZigLLVM_AMDGPU_LS = 95,
    ZigLLVM_AMDGPU_ES = 96,
    ZigLLVM_AArch64_VectorCall = 97,
    ZigLLVM_MaxID = 1023,
};

enum ZigLLVM_CallAttr {
    ZigLLVM_CallAttrAuto,
    ZigLLVM_CallAttrNeverTail,
    ZigLLVM_CallAttrNeverInline,
    ZigLLVM_CallAttrAlwaysTail,
    ZigLLVM_CallAttrAlwaysInline,
};
ZIG_EXTERN_C LLVMValueRef ZigLLVMBuildCall(LLVMBuilderRef B, LLVMValueRef Fn, LLVMValueRef *Args,
        unsigned NumArgs, enum ZigLLVM_CallingConv CC, enum ZigLLVM_CallAttr attr, const char *Name);

ZIG_EXTERN_C LLVMValueRef ZigLLVMBuildMemCpy(LLVMBuilderRef B, LLVMValueRef Dst, unsigned DstAlign,
        LLVMValueRef Src, unsigned SrcAlign, LLVMValueRef Size, bool isVolatile);

ZIG_EXTERN_C LLVMValueRef ZigLLVMBuildMemSet(LLVMBuilderRef B, LLVMValueRef Ptr, LLVMValueRef Val, LLVMValueRef Size,
        unsigned Align, bool isVolatile);

ZIG_EXTERN_C LLVMValueRef ZigLLVMBuildCmpXchg(LLVMBuilderRef builder, LLVMValueRef ptr, LLVMValueRef cmp,
        LLVMValueRef new_val, unsigned Align, LLVMAtomicOrdering success_ordering,
        LLVMAtomicOrdering failure_ordering, bool is_weak);

ZIG_EXTERN_C LLVMValueRef ZigLLVMBuildNSWShl(LLVMBuilderRef builder, LLVMValueRef LHS, LLVMValueRef RHS,
        const char *name);
ZIG_EXTERN_C LLVMValueRef ZigLLVMBuildNUWShl(LLVMBuilderRef builder, LLVMValueRef LHS, LLVMValueRef RHS,
        const char *name);
ZIG_EXTERN_C LLVMValueRef ZigLLVMBuildLShrExact(LLVMBuilderRef builder, LLVMValueRef LHS, LLVMValueRef RHS,
        const char *name);
ZIG_EXTERN_C LLVMValueRef ZigLLVMBuildAShrExact(LLVMBuilderRef builder, LLVMValueRef LHS, LLVMValueRef RHS,
        const char *name);

ZIG_EXTERN_C struct ZigLLVMDIType *ZigLLVMCreateDebugPointerType(struct ZigLLVMDIBuilder *dibuilder,
        struct ZigLLVMDIType *pointee_type, uint64_t size_in_bits, uint64_t align_in_bits, const char *name);

ZIG_EXTERN_C struct ZigLLVMDIType *ZigLLVMCreateDebugBasicType(struct ZigLLVMDIBuilder *dibuilder, const char *name,
        uint64_t size_in_bits, unsigned encoding);

ZIG_EXTERN_C struct ZigLLVMDIType *ZigLLVMCreateDebugArrayType(struct ZigLLVMDIBuilder *dibuilder,
        uint64_t size_in_bits, uint64_t align_in_bits, struct ZigLLVMDIType *elem_type,
        int elem_count);

ZIG_EXTERN_C struct ZigLLVMDIEnumerator *ZigLLVMCreateDebugEnumerator(struct ZigLLVMDIBuilder *dibuilder,
        const char *name, int64_t val);

ZIG_EXTERN_C struct ZigLLVMDIType *ZigLLVMCreateDebugEnumerationType(struct ZigLLVMDIBuilder *dibuilder,
        struct ZigLLVMDIScope *scope, const char *name, struct ZigLLVMDIFile *file, unsigned line_number,
        uint64_t size_in_bits, uint64_t align_in_bits, struct ZigLLVMDIEnumerator **enumerator_array,
        int enumerator_array_len, struct ZigLLVMDIType *underlying_type, const char *unique_id);

ZIG_EXTERN_C struct ZigLLVMDIType *ZigLLVMCreateDebugStructType(struct ZigLLVMDIBuilder *dibuilder,
        struct ZigLLVMDIScope *scope, const char *name, struct ZigLLVMDIFile *file, unsigned line_number,
        uint64_t size_in_bits, uint64_t align_in_bits, unsigned flags, struct ZigLLVMDIType *derived_from,
        struct ZigLLVMDIType **types_array, int types_array_len, unsigned run_time_lang,
        struct ZigLLVMDIType *vtable_holder, const char *unique_id);

ZIG_EXTERN_C struct ZigLLVMDIType *ZigLLVMCreateDebugUnionType(struct ZigLLVMDIBuilder *dibuilder,
        struct ZigLLVMDIScope *scope, const char *name, struct ZigLLVMDIFile *file, unsigned line_number,
        uint64_t size_in_bits, uint64_t align_in_bits, unsigned flags, struct ZigLLVMDIType **types_array,
        int types_array_len, unsigned run_time_lang, const char *unique_id);

ZIG_EXTERN_C struct ZigLLVMDIType *ZigLLVMCreateDebugMemberType(struct ZigLLVMDIBuilder *dibuilder,
        struct ZigLLVMDIScope *scope, const char *name, struct ZigLLVMDIFile *file, unsigned line,
        uint64_t size_in_bits, uint64_t align_in_bits, uint64_t offset_in_bits, unsigned flags,
        struct ZigLLVMDIType *type);

ZIG_EXTERN_C struct ZigLLVMDIType *ZigLLVMCreateReplaceableCompositeType(struct ZigLLVMDIBuilder *dibuilder,
        unsigned tag, const char *name, struct ZigLLVMDIScope *scope, struct ZigLLVMDIFile *file, unsigned line);

ZIG_EXTERN_C struct ZigLLVMDIType *ZigLLVMCreateDebugForwardDeclType(struct ZigLLVMDIBuilder *dibuilder, unsigned tag,
        const char *name, struct ZigLLVMDIScope *scope, struct ZigLLVMDIFile *file, unsigned line);

ZIG_EXTERN_C void ZigLLVMReplaceTemporary(struct ZigLLVMDIBuilder *dibuilder, struct ZigLLVMDIType *type,
        struct ZigLLVMDIType *replacement);

ZIG_EXTERN_C void ZigLLVMReplaceDebugArrays(struct ZigLLVMDIBuilder *dibuilder, struct ZigLLVMDIType *type,
        struct ZigLLVMDIType **types_array, int types_array_len);

ZIG_EXTERN_C struct ZigLLVMDIType *ZigLLVMCreateSubroutineType(struct ZigLLVMDIBuilder *dibuilder_wrapped,
        struct ZigLLVMDIType **types_array, int types_array_len, unsigned flags);

ZIG_EXTERN_C unsigned ZigLLVMEncoding_DW_ATE_unsigned(void);
ZIG_EXTERN_C unsigned ZigLLVMEncoding_DW_ATE_signed(void);
ZIG_EXTERN_C unsigned ZigLLVMEncoding_DW_ATE_float(void);
ZIG_EXTERN_C unsigned ZigLLVMEncoding_DW_ATE_boolean(void);
ZIG_EXTERN_C unsigned ZigLLVMEncoding_DW_ATE_unsigned_char(void);
ZIG_EXTERN_C unsigned ZigLLVMEncoding_DW_ATE_signed_char(void);
ZIG_EXTERN_C unsigned ZigLLVMLang_DW_LANG_C99(void);
ZIG_EXTERN_C unsigned ZigLLVMTag_DW_variable(void);
ZIG_EXTERN_C unsigned ZigLLVMTag_DW_structure_type(void);
ZIG_EXTERN_C unsigned ZigLLVMTag_DW_enumeration_type(void);
ZIG_EXTERN_C unsigned ZigLLVMTag_DW_union_type(void);

ZIG_EXTERN_C struct ZigLLVMDIBuilder *ZigLLVMCreateDIBuilder(LLVMModuleRef module, bool allow_unresolved);
ZIG_EXTERN_C void ZigLLVMDisposeDIBuilder(struct ZigLLVMDIBuilder *dbuilder);
ZIG_EXTERN_C void ZigLLVMAddModuleDebugInfoFlag(LLVMModuleRef module);
ZIG_EXTERN_C void ZigLLVMAddModuleCodeViewFlag(LLVMModuleRef module);
ZIG_EXTERN_C void ZigLLVMSetModulePICLevel(LLVMModuleRef module);
ZIG_EXTERN_C void ZigLLVMSetModulePIELevel(LLVMModuleRef module);
ZIG_EXTERN_C void ZigLLVMSetModuleCodeModel(LLVMModuleRef module, LLVMCodeModel code_model);

ZIG_EXTERN_C void ZigLLVMSetCurrentDebugLocation(LLVMBuilderRef builder, int line, int column,
        struct ZigLLVMDIScope *scope);
ZIG_EXTERN_C void ZigLLVMClearCurrentDebugLocation(LLVMBuilderRef builder);

ZIG_EXTERN_C struct ZigLLVMDIScope *ZigLLVMLexicalBlockToScope(struct ZigLLVMDILexicalBlock *lexical_block);
ZIG_EXTERN_C struct ZigLLVMDIScope *ZigLLVMCompileUnitToScope(struct ZigLLVMDICompileUnit *compile_unit);
ZIG_EXTERN_C struct ZigLLVMDIScope *ZigLLVMFileToScope(struct ZigLLVMDIFile *difile);
ZIG_EXTERN_C struct ZigLLVMDIScope *ZigLLVMSubprogramToScope(struct ZigLLVMDISubprogram *subprogram);
ZIG_EXTERN_C struct ZigLLVMDIScope *ZigLLVMTypeToScope(struct ZigLLVMDIType *type);

ZIG_EXTERN_C struct ZigLLVMDILocalVariable *ZigLLVMCreateAutoVariable(struct ZigLLVMDIBuilder *dbuilder,
        struct ZigLLVMDIScope *scope, const char *name, struct ZigLLVMDIFile *file, unsigned line_no,
        struct ZigLLVMDIType *type, bool always_preserve, unsigned flags);

ZIG_EXTERN_C struct ZigLLVMDIGlobalVariable *ZigLLVMCreateGlobalVariable(struct ZigLLVMDIBuilder *dbuilder,
    struct ZigLLVMDIScope *scope, const char *name, const char *linkage_name, struct ZigLLVMDIFile *file,
    unsigned line_no, struct ZigLLVMDIType *di_type, bool is_local_to_unit);

ZIG_EXTERN_C struct ZigLLVMDILocalVariable *ZigLLVMCreateParameterVariable(struct ZigLLVMDIBuilder *dbuilder,
        struct ZigLLVMDIScope *scope, const char *name, struct ZigLLVMDIFile *file, unsigned line_no,
        struct ZigLLVMDIType *type, bool always_preserve, unsigned flags, unsigned arg_no);

ZIG_EXTERN_C struct ZigLLVMDILexicalBlock *ZigLLVMCreateLexicalBlock(struct ZigLLVMDIBuilder *dbuilder,
        struct ZigLLVMDIScope *scope, struct ZigLLVMDIFile *file, unsigned line, unsigned col);

ZIG_EXTERN_C struct ZigLLVMDICompileUnit *ZigLLVMCreateCompileUnit(struct ZigLLVMDIBuilder *dibuilder,
        unsigned lang, struct ZigLLVMDIFile *difile, const char *producer,
        bool is_optimized, const char *flags, unsigned runtime_version, const char *split_name,
        uint64_t dwo_id, bool emit_debug_info);

ZIG_EXTERN_C struct ZigLLVMDIFile *ZigLLVMCreateFile(struct ZigLLVMDIBuilder *dibuilder, const char *filename,
        const char *directory);

ZIG_EXTERN_C struct ZigLLVMDISubprogram *ZigLLVMCreateFunction(struct ZigLLVMDIBuilder *dibuilder,
        struct ZigLLVMDIScope *scope, const char *name, const char *linkage_name, struct ZigLLVMDIFile *file,
        unsigned lineno, struct ZigLLVMDIType *fn_di_type, bool is_local_to_unit, bool is_definition,
        unsigned scope_line, unsigned flags, bool is_optimized, struct ZigLLVMDISubprogram *decl_subprogram);

ZIG_EXTERN_C struct ZigLLVMDIType *ZigLLVMDIBuilderCreateVectorType(struct ZigLLVMDIBuilder *dibuilder,
        uint64_t SizeInBits, uint32_t AlignInBits, struct ZigLLVMDIType *Ty, uint32_t elem_count);

ZIG_EXTERN_C void ZigLLVMFnSetSubprogram(LLVMValueRef fn, struct ZigLLVMDISubprogram *subprogram);

ZIG_EXTERN_C void ZigLLVMDIBuilderFinalize(struct ZigLLVMDIBuilder *dibuilder);

ZIG_EXTERN_C LLVMValueRef ZigLLVMInsertDeclareAtEnd(struct ZigLLVMDIBuilder *dibuilder, LLVMValueRef storage,
        struct ZigLLVMDILocalVariable *var_info, struct ZigLLVMDILocation *debug_loc,
        LLVMBasicBlockRef basic_block_ref);

ZIG_EXTERN_C LLVMValueRef ZigLLVMInsertDeclare(struct ZigLLVMDIBuilder *dibuilder, LLVMValueRef storage,
        struct ZigLLVMDILocalVariable *var_info, struct ZigLLVMDILocation *debug_loc, LLVMValueRef insert_before_instr);
ZIG_EXTERN_C struct ZigLLVMDILocation *ZigLLVMGetDebugLoc(unsigned line, unsigned col, struct ZigLLVMDIScope *scope);

ZIG_EXTERN_C void ZigLLVMSetFastMath(LLVMBuilderRef builder_wrapped, bool on_state);
ZIG_EXTERN_C void ZigLLVMSetTailCall(LLVMValueRef Call);
ZIG_EXTERN_C void ZigLLVMSetCallSret(LLVMValueRef Call, LLVMTypeRef return_type);
ZIG_EXTERN_C void ZigLLVMFunctionSetPrefixData(LLVMValueRef fn, LLVMValueRef data);
ZIG_EXTERN_C void ZigLLVMFunctionSetCallingConv(LLVMValueRef function, enum ZigLLVM_CallingConv cc);

ZIG_EXTERN_C void ZigLLVMAddFunctionAttr(LLVMValueRef fn, const char *attr_name, const char *attr_value);
ZIG_EXTERN_C void ZigLLVMAddByValAttr(LLVMValueRef fn_ref, unsigned ArgNo, LLVMTypeRef type_val);
ZIG_EXTERN_C void ZigLLVMAddSretAttr(LLVMValueRef fn_ref, unsigned ArgNo, LLVMTypeRef type_val);
ZIG_EXTERN_C void ZigLLVMAddFunctionAttrCold(LLVMValueRef fn);

ZIG_EXTERN_C void ZigLLVMParseCommandLineOptions(size_t argc, const char *const *argv);


// copied from include/llvm/ADT/Triple.h
// synchronize with target.cpp::arch_list
enum ZigLLVM_ArchType {
    ZigLLVM_UnknownArch,

    ZigLLVM_arm,            // ARM (little endian): arm, armv.*, xscale
    ZigLLVM_armeb,          // ARM (big endian): armeb
    ZigLLVM_aarch64,        // AArch64 (little endian): aarch64
    ZigLLVM_aarch64_be,     // AArch64 (big endian): aarch64_be
    ZigLLVM_aarch64_32,     // AArch64 (little endian) ILP32: aarch64_32
    ZigLLVM_arc,            // ARC: Synopsys ARC
    ZigLLVM_avr,            // AVR: Atmel AVR microcontroller
    ZigLLVM_bpfel,          // eBPF or extended BPF or 64-bit BPF (little endian)
    ZigLLVM_bpfeb,          // eBPF or extended BPF or 64-bit BPF (big endian)
    ZigLLVM_csky,           // CSKY: csky
    ZigLLVM_hexagon,        // Hexagon: hexagon
    ZigLLVM_m68k,           // M68K: m680x0
    ZigLLVM_mips,           // MIPS: mips, mipsallegrex, mipsr6
    ZigLLVM_mipsel,         // MIPSEL: mipsel, mipsallegrexe, mipsr6el
    ZigLLVM_mips64,         // MIPS64: mips64, mips64r6, mipsn32, mipsn32r6
    ZigLLVM_mips64el,       // MIPS64EL: mips64el, mips64r6el, mipsn32el, mipsn32r6el
    ZigLLVM_msp430,         // MSP430: msp430
    ZigLLVM_ppc,            // PPC: powerpc
    ZigLLVM_ppcle,          // PPCLE: powerpc (little endian)
    ZigLLVM_ppc64,          // PPC64: powerpc64, ppu
    ZigLLVM_ppc64le,        // PPC64LE: powerpc64le
    ZigLLVM_r600,           // R600: AMD GPUs HD2XXX - HD6XXX
    ZigLLVM_amdgcn,         // AMDGCN: AMD GCN GPUs
    ZigLLVM_riscv32,        // RISC-V (32-bit): riscv32
    ZigLLVM_riscv64,        // RISC-V (64-bit): riscv64
    ZigLLVM_sparc,          // Sparc: sparc
    ZigLLVM_sparcv9,        // Sparcv9: Sparcv9
    ZigLLVM_sparcel,        // Sparc: (endianness = little). NB: 'Sparcle' is a CPU variant
    ZigLLVM_systemz,        // SystemZ: s390x
    ZigLLVM_tce,            // TCE (http://tce.cs.tut.fi/): tce
    ZigLLVM_tcele,          // TCE little endian (http://tce.cs.tut.fi/): tcele
    ZigLLVM_thumb,          // Thumb (little endian): thumb, thumbv.*
    ZigLLVM_thumbeb,        // Thumb (big endian): thumbeb
    ZigLLVM_x86,            // X86: i[3-9]86
    ZigLLVM_x86_64,         // X86-64: amd64, x86_64
    ZigLLVM_xcore,          // XCore: xcore
    ZigLLVM_nvptx,          // NVPTX: 32-bit
    ZigLLVM_nvptx64,        // NVPTX: 64-bit
    ZigLLVM_le32,           // le32: generic little-endian 32-bit CPU (PNaCl)
    ZigLLVM_le64,           // le64: generic little-endian 64-bit CPU (PNaCl)
    ZigLLVM_amdil,          // AMDIL
    ZigLLVM_amdil64,        // AMDIL with 64-bit pointers
    ZigLLVM_hsail,          // AMD HSAIL
    ZigLLVM_hsail64,        // AMD HSAIL with 64-bit pointers
    ZigLLVM_spir,           // SPIR: standard portable IR for OpenCL 32-bit version
    ZigLLVM_spir64,         // SPIR: standard portable IR for OpenCL 64-bit version
    ZigLLVM_kalimba,        // Kalimba: generic kalimba
    ZigLLVM_shave,          // SHAVE: Movidius vector VLIW processors
    ZigLLVM_lanai,          // Lanai: Lanai 32-bit
    ZigLLVM_wasm32,         // WebAssembly with 32-bit pointers
    ZigLLVM_wasm64,         // WebAssembly with 64-bit pointers
    ZigLLVM_renderscript32, // 32-bit RenderScript
    ZigLLVM_renderscript64, // 64-bit RenderScript
    ZigLLVM_ve,             // NEC SX-Aurora Vector Engine

    ZigLLVM_LastArchType = ZigLLVM_ve
};

enum ZigLLVM_VendorType {
    ZigLLVM_UnknownVendor,

    ZigLLVM_Apple,
    ZigLLVM_PC,
    ZigLLVM_SCEI,
    ZigLLVM_Freescale,
    ZigLLVM_IBM,
    ZigLLVM_ImaginationTechnologies,
    ZigLLVM_MipsTechnologies,
    ZigLLVM_NVIDIA,
    ZigLLVM_CSR,
    ZigLLVM_Myriad,
    ZigLLVM_AMD,
    ZigLLVM_Mesa,
    ZigLLVM_SUSE,
    ZigLLVM_OpenEmbedded,

    ZigLLVM_LastVendorType = ZigLLVM_OpenEmbedded
};

enum ZigLLVM_OSType {
    ZigLLVM_UnknownOS,

    ZigLLVM_Ananas,
    ZigLLVM_CloudABI,
    ZigLLVM_Darwin,
    ZigLLVM_DragonFly,
    ZigLLVM_FreeBSD,
    ZigLLVM_Fuchsia,
    ZigLLVM_IOS,
    ZigLLVM_KFreeBSD,
    ZigLLVM_Linux,
    ZigLLVM_Lv2,        // PS3
    ZigLLVM_MacOSX,
    ZigLLVM_NetBSD,
    ZigLLVM_OpenBSD,
    ZigLLVM_Solaris,
    ZigLLVM_Win32,
    ZigLLVM_ZOS,
    ZigLLVM_Haiku,
    ZigLLVM_Minix,
    ZigLLVM_RTEMS,
    ZigLLVM_NaCl,       // Native Client
    ZigLLVM_AIX,
    ZigLLVM_CUDA,       // NVIDIA CUDA
    ZigLLVM_NVCL,       // NVIDIA OpenCL
    ZigLLVM_AMDHSA,     // AMD HSA Runtime
    ZigLLVM_PS4,
    ZigLLVM_ELFIAMCU,
    ZigLLVM_TvOS,       // Apple tvOS
    ZigLLVM_WatchOS,    // Apple watchOS
    ZigLLVM_Mesa3D,
    ZigLLVM_Contiki,
    ZigLLVM_AMDPAL,     // AMD PAL Runtime
    ZigLLVM_HermitCore, // HermitCore Unikernel/Multikernel
    ZigLLVM_Hurd,       // GNU/Hurd
    ZigLLVM_WASI,       // Experimental WebAssembly OS
    ZigLLVM_Emscripten,

    ZigLLVM_LastOSType = ZigLLVM_Emscripten
};

// Synchronize with target.cpp::abi_list
enum ZigLLVM_EnvironmentType {
    ZigLLVM_UnknownEnvironment,

    ZigLLVM_GNU,
    ZigLLVM_GNUABIN32,
    ZigLLVM_GNUABI64,
    ZigLLVM_GNUEABI,
    ZigLLVM_GNUEABIHF,
    ZigLLVM_GNUX32,
    ZigLLVM_GNUILP32,
    ZigLLVM_CODE16,
    ZigLLVM_EABI,
    ZigLLVM_EABIHF,
    ZigLLVM_Android,
    ZigLLVM_Musl,
    ZigLLVM_MuslEABI,
    ZigLLVM_MuslEABIHF,
    ZigLLVM_MuslX32,

    ZigLLVM_MSVC,
    ZigLLVM_Itanium,
    ZigLLVM_Cygnus,
    ZigLLVM_CoreCLR,
    ZigLLVM_Simulator, // Simulator variants of other systems, e.g., Apple's iOS
    ZigLLVM_MacABI, // Mac Catalyst variant of Apple's iOS deployment target.

    ZigLLVM_LastEnvironmentType = ZigLLVM_MacABI
};

enum ZigLLVM_ObjectFormatType {
    ZigLLVM_UnknownObjectFormat,

    ZigLLVM_COFF,
    ZigLLVM_ELF,
    ZigLLVM_GOFF,
    ZigLLVM_MachO,
    ZigLLVM_Wasm,
    ZigLLVM_XCOFF,
};

enum ZigLLVM_AtomicRMWBinOp {
    ZigLLVMAtomicRMWBinOpXchg,
    ZigLLVMAtomicRMWBinOpAdd,
    ZigLLVMAtomicRMWBinOpSub,
    ZigLLVMAtomicRMWBinOpAnd,
    ZigLLVMAtomicRMWBinOpNand,
    ZigLLVMAtomicRMWBinOpOr,
    ZigLLVMAtomicRMWBinOpXor,
    ZigLLVMAtomicRMWBinOpMax,
    ZigLLVMAtomicRMWBinOpMin,
    ZigLLVMAtomicRMWBinOpUMax,
    ZigLLVMAtomicRMWBinOpUMin,
    ZigLLVMAtomicRMWBinOpFAdd,
    ZigLLVMAtomicRMWBinOpFSub,
};

LLVMValueRef ZigLLVMBuildAtomicRMW(LLVMBuilderRef B, enum ZigLLVM_AtomicRMWBinOp op,
    LLVMValueRef PTR, LLVMValueRef Val, unsigned Align,
    LLVMAtomicOrdering ordering, LLVMBool singleThread);

LLVMValueRef ZigLLVMBuildAndReduce(LLVMBuilderRef B, LLVMValueRef Val);
LLVMValueRef ZigLLVMBuildOrReduce(LLVMBuilderRef B, LLVMValueRef Val);
LLVMValueRef ZigLLVMBuildXorReduce(LLVMBuilderRef B, LLVMValueRef Val);
LLVMValueRef ZigLLVMBuildIntMaxReduce(LLVMBuilderRef B, LLVMValueRef Val, bool is_signed);
LLVMValueRef ZigLLVMBuildIntMinReduce(LLVMBuilderRef B, LLVMValueRef Val, bool is_signed);
LLVMValueRef ZigLLVMBuildFPMaxReduce(LLVMBuilderRef B, LLVMValueRef Val);
LLVMValueRef ZigLLVMBuildFPMinReduce(LLVMBuilderRef B, LLVMValueRef Val);
LLVMValueRef ZigLLVMBuildAddReduce(LLVMBuilderRef B, LLVMValueRef Val);
LLVMValueRef ZigLLVMBuildMulReduce(LLVMBuilderRef B, LLVMValueRef Val);
LLVMValueRef ZigLLVMBuildFPAddReduce(LLVMBuilderRef B, LLVMValueRef Acc, LLVMValueRef Val);
LLVMValueRef ZigLLVMBuildFPMulReduce(LLVMBuilderRef B, LLVMValueRef Acc, LLVMValueRef Val);

#define ZigLLVM_DIFlags_Zero 0U
#define ZigLLVM_DIFlags_Private 1U
#define ZigLLVM_DIFlags_Protected 2U
#define ZigLLVM_DIFlags_Public 3U
#define ZigLLVM_DIFlags_FwdDecl (1U << 2)
#define ZigLLVM_DIFlags_AppleBlock (1U << 3)
#define ZigLLVM_DIFlags_BlockByrefStruct (1U << 4)
#define ZigLLVM_DIFlags_Virtual (1U << 5)
#define ZigLLVM_DIFlags_Artificial (1U << 6)
#define ZigLLVM_DIFlags_Explicit (1U << 7)
#define ZigLLVM_DIFlags_Prototyped (1U << 8)
#define ZigLLVM_DIFlags_ObjcClassComplete (1U << 9)
#define ZigLLVM_DIFlags_ObjectPointer (1U << 10)
#define ZigLLVM_DIFlags_Vector (1U << 11)
#define ZigLLVM_DIFlags_StaticMember (1U << 12)
#define ZigLLVM_DIFlags_LValueReference (1U << 13)
#define ZigLLVM_DIFlags_RValueReference (1U << 14)
#define ZigLLVM_DIFlags_Reserved (1U << 15)
#define ZigLLVM_DIFlags_SingleInheritance (1U << 16)
#define ZigLLVM_DIFlags_MultipleInheritance (2 << 16)
#define ZigLLVM_DIFlags_VirtualInheritance (3 << 16)
#define ZigLLVM_DIFlags_IntroducedVirtual (1U << 18)
#define ZigLLVM_DIFlags_BitField (1U << 19)
#define ZigLLVM_DIFlags_NoReturn (1U << 20)
#define ZigLLVM_DIFlags_TypePassByValue (1U << 22)
#define ZigLLVM_DIFlags_TypePassByReference (1U << 23)
#define ZigLLVM_DIFlags_EnumClass (1U << 24)
#define ZigLLVM_DIFlags_Thunk (1U << 25)
#define ZigLLVM_DIFlags_NonTrivial (1U << 26)
#define ZigLLVM_DIFlags_BigEndian (1U << 27)
#define ZigLLVM_DIFlags_LittleEndian (1U << 28)
#define ZigLLVM_DIFlags_AllCallsDescribed (1U << 29)

ZIG_EXTERN_C const char *ZigLLVMGetArchTypeName(enum ZigLLVM_ArchType arch);
ZIG_EXTERN_C const char *ZigLLVMGetVendorTypeName(enum ZigLLVM_VendorType vendor);
ZIG_EXTERN_C const char *ZigLLVMGetOSTypeName(enum ZigLLVM_OSType os);
ZIG_EXTERN_C const char *ZigLLVMGetEnvironmentTypeName(enum ZigLLVM_EnvironmentType abi);

ZIG_EXTERN_C int ZigLLDLinkCOFF(int argc, const char **argv, bool can_exit_early);
ZIG_EXTERN_C int ZigLLDLinkELF(int argc, const char **argv, bool can_exit_early);
ZIG_EXTERN_C int ZigLLDLinkWasm(int argc, const char **argv, bool can_exit_early);

ZIG_EXTERN_C bool ZigLLVMWriteArchive(const char *archive_name, const char **file_names, size_t file_name_count,
        enum ZigLLVM_OSType os_type);

ZIG_EXTERN_C bool ZigLLVMWriteImportLibrary(const char *def_path, const enum ZigLLVM_ArchType arch,
                               const char *output_lib_path, bool kill_at);

ZIG_EXTERN_C void ZigLLVMGetNativeTarget(enum ZigLLVM_ArchType *arch_type,
        enum ZigLLVM_VendorType *vendor_type, enum ZigLLVM_OSType *os_type, enum ZigLLVM_EnvironmentType *environ_type,
        enum ZigLLVM_ObjectFormatType *oformat);

ZIG_EXTERN_C unsigned ZigLLVMDataLayoutGetStackAlignment(LLVMTargetDataRef TD);
ZIG_EXTERN_C unsigned ZigLLVMDataLayoutGetProgramAddressSpace(LLVMTargetDataRef TD);

#endif
