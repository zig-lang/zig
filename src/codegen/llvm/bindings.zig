//! We do this instead of @cImport because the self-hosted compiler is easier
//! to bootstrap if it does not depend on translate-c.

/// Do not compare directly to .True, use toBool() instead.
pub const Bool = enum(c_int) {
    False,
    True,
    _,

    pub fn fromBool(b: bool) Bool {
        return @intToEnum(Bool, @boolToInt(b));
    }

    pub fn toBool(b: Bool) bool {
        return b != .False;
    }
};
pub const AttributeIndex = c_uint;

/// Make sure to use the *InContext functions instead of the global ones.
pub const Context = opaque {
    pub const create = LLVMContextCreate;
    extern fn LLVMContextCreate() *const Context;

    pub const dispose = LLVMContextDispose;
    extern fn LLVMContextDispose(C: *const Context) void;

    pub const createEnumAttribute = LLVMCreateEnumAttribute;
    extern fn LLVMCreateEnumAttribute(*const Context, KindID: c_uint, Val: u64) *const Attribute;

    pub const intType = LLVMIntTypeInContext;
    extern fn LLVMIntTypeInContext(C: *const Context, NumBits: c_uint) *const Type;

    pub const voidType = LLVMVoidTypeInContext;
    extern fn LLVMVoidTypeInContext(C: *const Context) *const Type;

    pub const structType = LLVMStructTypeInContext;
    extern fn LLVMStructTypeInContext(C: *const Context, ElementTypes: [*]*const Type, ElementCount: c_uint, Packed: Bool) *const Type;

    pub const constString = LLVMConstStringInContext;
    extern fn LLVMConstStringInContext(C: *const Context, Str: [*]const u8, Length: c_uint, DontNullTerminate: Bool) *const Value;

    pub const constStruct = LLVMConstStructInContext;
    extern fn LLVMConstStructInContext(C: *const Context, ConstantVals: [*]*const Value, Count: c_uint, Packed: Bool) *const Value;

    pub const createBasicBlock = LLVMCreateBasicBlockInContext;
    extern fn LLVMCreateBasicBlockInContext(C: *const Context, Name: [*:0]const u8) *const BasicBlock;

    pub const appendBasicBlock = LLVMAppendBasicBlockInContext;
    extern fn LLVMAppendBasicBlockInContext(C: *const Context, Fn: *const Value, Name: [*:0]const u8) *const BasicBlock;

    pub const createBuilder = LLVMCreateBuilderInContext;
    extern fn LLVMCreateBuilderInContext(C: *const Context) *const Builder;
};

pub const Value = opaque {
    pub const addAttributeAtIndex = LLVMAddAttributeAtIndex;
    extern fn LLVMAddAttributeAtIndex(*const Value, Idx: AttributeIndex, A: *const Attribute) void;

    pub const getFirstBasicBlock = LLVMGetFirstBasicBlock;
    extern fn LLVMGetFirstBasicBlock(Fn: *const Value) ?*const BasicBlock;

    pub const appendExistingBasicBlock = LLVMAppendExistingBasicBlock;
    extern fn LLVMAppendExistingBasicBlock(Fn: *const Value, BB: *const BasicBlock) void;

    pub const addIncoming = LLVMAddIncoming;
    extern fn LLVMAddIncoming(PhiNode: *const Value, IncomingValues: [*]*const Value, IncomingBlocks: [*]*const BasicBlock, Count: c_uint) void;

    pub const getNextInstruction = LLVMGetNextInstruction;
    extern fn LLVMGetNextInstruction(Inst: *const Value) ?*const Value;
};

pub const Type = opaque {
    pub const functionType = LLVMFunctionType;
    extern fn LLVMFunctionType(ReturnType: *const Type, ParamTypes: ?[*]*const Type, ParamCount: c_uint, IsVarArg: Bool) *const Type;

    pub const constNull = LLVMConstNull;
    extern fn LLVMConstNull(Ty: *const Type) *const Value;

    pub const constAllOnes = LLVMConstAllOnes;
    extern fn LLVMConstAllOnes(Ty: *const Type) *const Value;

    pub const constInt = LLVMConstInt;
    extern fn LLVMConstInt(IntTy: *const Type, N: c_ulonglong, SignExtend: Bool) *const Value;

    pub const constArray = LLVMConstArray;
    extern fn LLVMConstArray(ElementTy: *const Type, ConstantVals: ?[*]*const Value, Length: c_uint) *const Value;

    pub const getUndef = LLVMGetUndef;
    extern fn LLVMGetUndef(Ty: *const Type) *const Value;

    pub const pointerType = LLVMPointerType;
    extern fn LLVMPointerType(ElementType: *const Type, AddressSpace: c_uint) *const Type;

    pub const arrayType = LLVMArrayType;
    extern fn LLVMArrayType(ElementType: *const Type, ElementCount: c_uint) *const Type;
};

pub const Module = opaque {
    pub const createWithName = LLVMModuleCreateWithNameInContext;
    extern fn LLVMModuleCreateWithNameInContext(ModuleID: [*:0]const u8, C: *const Context) *const Module;

    pub const dispose = LLVMDisposeModule;
    extern fn LLVMDisposeModule(*const Module) void;

    pub const verify = LLVMVerifyModule;
    extern fn LLVMVerifyModule(*const Module, Action: VerifierFailureAction, OutMessage: *[*:0]const u8) Bool;

    pub const addFunction = LLVMAddFunction;
    extern fn LLVMAddFunction(*const Module, Name: [*:0]const u8, FunctionTy: *const Type) *const Value;

    pub const getNamedFunction = LLVMGetNamedFunction;
    extern fn LLVMGetNamedFunction(*const Module, Name: [*:0]const u8) ?*const Value;

    pub const getIntrinsicDeclaration = LLVMGetIntrinsicDeclaration;
    extern fn LLVMGetIntrinsicDeclaration(Mod: *const Module, ID: c_uint, ParamTypes: ?[*]*const Type, ParamCount: usize) *const Value;

    pub const printToString = LLVMPrintModuleToString;
    extern fn LLVMPrintModuleToString(*const Module) [*:0]const u8;

    pub const addGlobal = LLVMAddGlobal;
    extern fn LLVMAddGlobal(M: *const Module, Ty: *const Type, Name: [*:0]const u8) *const Value;

    pub const getNamedGlobal = LLVMGetNamedGlobal;
    extern fn LLVMGetNamedGlobal(M: *const Module, Name: [*:0]const u8) ?*const Value;
};

pub const lookupIntrinsicID = LLVMLookupIntrinsicID;
extern fn LLVMLookupIntrinsicID(Name: [*]const u8, NameLen: usize) c_uint;

pub const disposeMessage = LLVMDisposeMessage;
extern fn LLVMDisposeMessage(Message: [*:0]const u8) void;

pub const VerifierFailureAction = enum(c_int) {
    AbortProcess,
    PrintMessage,
    ReturnStatus,
};

pub const constNeg = LLVMConstNeg;
extern fn LLVMConstNeg(ConstantVal: *const Value) *const Value;

pub const setInitializer = LLVMSetInitializer;
extern fn LLVMSetInitializer(GlobalVar: *const Value, ConstantVal: *const Value) void;

pub const getParam = LLVMGetParam;
extern fn LLVMGetParam(Fn: *const Value, Index: c_uint) *const Value;

pub const getEnumAttributeKindForName = LLVMGetEnumAttributeKindForName;
extern fn LLVMGetEnumAttributeKindForName(Name: [*]const u8, SLen: usize) c_uint;

pub const Attribute = opaque {};

pub const Builder = opaque {
    pub const dispose = LLVMDisposeBuilder;
    extern fn LLVMDisposeBuilder(Builder: *const Builder) void;

    pub const positionBuilder = LLVMPositionBuilder;
    extern fn LLVMPositionBuilder(Builder: *const Builder, Block: *const BasicBlock, Instr: *const Value) void;

    pub const positionBuilderAtEnd = LLVMPositionBuilderAtEnd;
    extern fn LLVMPositionBuilderAtEnd(Builder: *const Builder, Block: *const BasicBlock) void;

    pub const getInsertBlock = LLVMGetInsertBlock;
    extern fn LLVMGetInsertBlock(Builder: *const Builder) *const BasicBlock;

    pub const buildCall = LLVMBuildCall;
    extern fn LLVMBuildCall(*const Builder, Fn: *const Value, Args: ?[*]*const Value, NumArgs: c_uint, Name: [*:0]const u8) *const Value;

    pub const buildCall2 = LLVMBuildCall2;
    extern fn LLVMBuildCall2(*const Builder, *const Type, Fn: *const Value, Args: [*]*const Value, NumArgs: c_uint, Name: [*:0]const u8) *const Value;

    pub const buildRetVoid = LLVMBuildRetVoid;
    extern fn LLVMBuildRetVoid(*const Builder) *const Value;

    pub const buildRet = LLVMBuildRet;
    extern fn LLVMBuildRet(*const Builder, V: *const Value) *const Value;

    pub const buildUnreachable = LLVMBuildUnreachable;
    extern fn LLVMBuildUnreachable(*const Builder) *const Value;

    pub const buildAlloca = LLVMBuildAlloca;
    extern fn LLVMBuildAlloca(*const Builder, Ty: *const Type, Name: [*:0]const u8) *const Value;

    pub const buildStore = LLVMBuildStore;
    extern fn LLVMBuildStore(*const Builder, Val: *const Value, Ptr: *const Value) *const Value;

    pub const buildLoad = LLVMBuildLoad;
    extern fn LLVMBuildLoad(*const Builder, PointerVal: *const Value, Name: [*:0]const u8) *const Value;

    pub const buildNot = LLVMBuildNot;
    extern fn LLVMBuildNot(*const Builder, V: *const Value, Name: [*:0]const u8) *const Value;

    pub const buildNSWAdd = LLVMBuildNSWAdd;
    extern fn LLVMBuildNSWAdd(*const Builder, LHS: *const Value, RHS: *const Value, Name: [*:0]const u8) *const Value;

    pub const buildNUWAdd = LLVMBuildNUWAdd;
    extern fn LLVMBuildNUWAdd(*const Builder, LHS: *const Value, RHS: *const Value, Name: [*:0]const u8) *const Value;

    pub const buildNSWSub = LLVMBuildNSWSub;
    extern fn LLVMBuildNSWSub(*const Builder, LHS: *const Value, RHS: *const Value, Name: [*:0]const u8) *const Value;

    pub const buildNUWSub = LLVMBuildNUWSub;
    extern fn LLVMBuildNUWSub(*const Builder, LHS: *const Value, RHS: *const Value, Name: [*:0]const u8) *const Value;

    pub const buildIntCast2 = LLVMBuildIntCast2;
    extern fn LLVMBuildIntCast2(*const Builder, Val: *const Value, DestTy: *const Type, IsSigned: Bool, Name: [*:0]const u8) *const Value;

    pub const buildBitCast = LLVMBuildBitCast;
    extern fn LLVMBuildBitCast(*const Builder, Val: *const Value, DestTy: *const Type, Name: [*:0]const u8) *const Value;

    pub const buildInBoundsGEP = LLVMBuildInBoundsGEP;
    extern fn LLVMBuildInBoundsGEP(B: *const Builder, Pointer: *const Value, Indices: [*]*const Value, NumIndices: c_uint, Name: [*:0]const u8) *const Value;

    pub const buildICmp = LLVMBuildICmp;
    extern fn LLVMBuildICmp(*const Builder, Op: IntPredicate, LHS: *const Value, RHS: *const Value, Name: [*:0]const u8) *const Value;

    pub const buildBr = LLVMBuildBr;
    extern fn LLVMBuildBr(*const Builder, Dest: *const BasicBlock) *const Value;

    pub const buildCondBr = LLVMBuildCondBr;
    extern fn LLVMBuildCondBr(*const Builder, If: *const Value, Then: *const BasicBlock, Else: *const BasicBlock) *const Value;

    pub const buildPhi = LLVMBuildPhi;
    extern fn LLVMBuildPhi(*const Builder, Ty: *const Type, Name: [*:0]const u8) *const Value;

    pub const buildExtractValue = LLVMBuildExtractValue;
    extern fn LLVMBuildExtractValue(*const Builder, AggVal: *const Value, Index: c_uint, Name: [*:0]const u8) *const Value;
};

pub const IntPredicate = enum(c_int) {
    EQ = 32,
    NE = 33,
    UGT = 34,
    UGE = 35,
    ULT = 36,
    ULE = 37,
    SGT = 38,
    SGE = 39,
    SLT = 40,
    SLE = 41,
};

pub const BasicBlock = opaque {
    pub const deleteBasicBlock = LLVMDeleteBasicBlock;
    extern fn LLVMDeleteBasicBlock(BB: *const BasicBlock) void;

    pub const getFirstInstruction = LLVMGetFirstInstruction;
    extern fn LLVMGetFirstInstruction(BB: *const BasicBlock) ?*const Value;
};

pub const TargetMachine = opaque {
    pub const create = LLVMCreateTargetMachine;
    extern fn LLVMCreateTargetMachine(
        T: *const Target,
        Triple: [*:0]const u8,
        CPU: [*:0]const u8,
        Features: [*:0]const u8,
        Level: CodeGenOptLevel,
        Reloc: RelocMode,
        CodeModel: CodeMode,
    ) *const TargetMachine;

    pub const dispose = LLVMDisposeTargetMachine;
    extern fn LLVMDisposeTargetMachine(T: *const TargetMachine) void;

    pub const emitToFile = LLVMTargetMachineEmitToFile;
    extern fn LLVMTargetMachineEmitToFile(
        *const TargetMachine,
        M: *const Module,
        Filename: [*:0]const u8,
        codegen: CodeGenFileType,
        ErrorMessage: *[*:0]const u8,
    ) Bool;
};

pub const CodeMode = enum(c_int) {
    Default,
    JITDefault,
    Tiny,
    Small,
    Kernel,
    Medium,
    Large,
};

pub const CodeGenOptLevel = enum(c_int) {
    None,
    Less,
    Default,
    Aggressive,
};

pub const RelocMode = enum(c_int) {
    Default,
    Static,
    PIC,
    DynamicNoPic,
    ROPI,
    RWPI,
    ROPI_RWPI,
};

pub const CodeGenFileType = enum(c_int) {
    AssemblyFile,
    ObjectFile,
};

pub const Target = opaque {
    pub const getFromTriple = LLVMGetTargetFromTriple;
    extern fn LLVMGetTargetFromTriple(Triple: [*:0]const u8, T: **const Target, ErrorMessage: *[*:0]const u8) Bool;
};

extern fn LLVMInitializeAArch64TargetInfo() void;
extern fn LLVMInitializeAMDGPUTargetInfo() void;
extern fn LLVMInitializeARMTargetInfo() void;
extern fn LLVMInitializeAVRTargetInfo() void;
extern fn LLVMInitializeBPFTargetInfo() void;
extern fn LLVMInitializeHexagonTargetInfo() void;
extern fn LLVMInitializeLanaiTargetInfo() void;
extern fn LLVMInitializeMipsTargetInfo() void;
extern fn LLVMInitializeMSP430TargetInfo() void;
extern fn LLVMInitializeNVPTXTargetInfo() void;
extern fn LLVMInitializePowerPCTargetInfo() void;
extern fn LLVMInitializeRISCVTargetInfo() void;
extern fn LLVMInitializeSparcTargetInfo() void;
extern fn LLVMInitializeSystemZTargetInfo() void;
extern fn LLVMInitializeWebAssemblyTargetInfo() void;
extern fn LLVMInitializeX86TargetInfo() void;
extern fn LLVMInitializeXCoreTargetInfo() void;
extern fn LLVMInitializeAArch64Target() void;
extern fn LLVMInitializeAMDGPUTarget() void;
extern fn LLVMInitializeARMTarget() void;
extern fn LLVMInitializeAVRTarget() void;
extern fn LLVMInitializeBPFTarget() void;
extern fn LLVMInitializeHexagonTarget() void;
extern fn LLVMInitializeLanaiTarget() void;
extern fn LLVMInitializeMipsTarget() void;
extern fn LLVMInitializeMSP430Target() void;
extern fn LLVMInitializeNVPTXTarget() void;
extern fn LLVMInitializePowerPCTarget() void;
extern fn LLVMInitializeRISCVTarget() void;
extern fn LLVMInitializeSparcTarget() void;
extern fn LLVMInitializeSystemZTarget() void;
extern fn LLVMInitializeWebAssemblyTarget() void;
extern fn LLVMInitializeX86Target() void;
extern fn LLVMInitializeXCoreTarget() void;
extern fn LLVMInitializeAArch64TargetMC() void;
extern fn LLVMInitializeAMDGPUTargetMC() void;
extern fn LLVMInitializeARMTargetMC() void;
extern fn LLVMInitializeAVRTargetMC() void;
extern fn LLVMInitializeBPFTargetMC() void;
extern fn LLVMInitializeHexagonTargetMC() void;
extern fn LLVMInitializeLanaiTargetMC() void;
extern fn LLVMInitializeMipsTargetMC() void;
extern fn LLVMInitializeMSP430TargetMC() void;
extern fn LLVMInitializeNVPTXTargetMC() void;
extern fn LLVMInitializePowerPCTargetMC() void;
extern fn LLVMInitializeRISCVTargetMC() void;
extern fn LLVMInitializeSparcTargetMC() void;
extern fn LLVMInitializeSystemZTargetMC() void;
extern fn LLVMInitializeWebAssemblyTargetMC() void;
extern fn LLVMInitializeX86TargetMC() void;
extern fn LLVMInitializeXCoreTargetMC() void;
extern fn LLVMInitializeAArch64AsmPrinter() void;
extern fn LLVMInitializeAMDGPUAsmPrinter() void;
extern fn LLVMInitializeARMAsmPrinter() void;
extern fn LLVMInitializeAVRAsmPrinter() void;
extern fn LLVMInitializeBPFAsmPrinter() void;
extern fn LLVMInitializeHexagonAsmPrinter() void;
extern fn LLVMInitializeLanaiAsmPrinter() void;
extern fn LLVMInitializeMipsAsmPrinter() void;
extern fn LLVMInitializeMSP430AsmPrinter() void;
extern fn LLVMInitializeNVPTXAsmPrinter() void;
extern fn LLVMInitializePowerPCAsmPrinter() void;
extern fn LLVMInitializeRISCVAsmPrinter() void;
extern fn LLVMInitializeSparcAsmPrinter() void;
extern fn LLVMInitializeSystemZAsmPrinter() void;
extern fn LLVMInitializeWebAssemblyAsmPrinter() void;
extern fn LLVMInitializeX86AsmPrinter() void;
extern fn LLVMInitializeXCoreAsmPrinter() void;
extern fn LLVMInitializeAArch64AsmParser() void;
extern fn LLVMInitializeAMDGPUAsmParser() void;
extern fn LLVMInitializeARMAsmParser() void;
extern fn LLVMInitializeAVRAsmParser() void;
extern fn LLVMInitializeBPFAsmParser() void;
extern fn LLVMInitializeHexagonAsmParser() void;
extern fn LLVMInitializeLanaiAsmParser() void;
extern fn LLVMInitializeMipsAsmParser() void;
extern fn LLVMInitializeMSP430AsmParser() void;
extern fn LLVMInitializePowerPCAsmParser() void;
extern fn LLVMInitializeRISCVAsmParser() void;
extern fn LLVMInitializeSparcAsmParser() void;
extern fn LLVMInitializeSystemZAsmParser() void;
extern fn LLVMInitializeWebAssemblyAsmParser() void;
extern fn LLVMInitializeX86AsmParser() void;

pub const initializeAllTargetInfos = LLVMInitializeAllTargetInfos;
fn LLVMInitializeAllTargetInfos() callconv(.C) void {
    LLVMInitializeAArch64TargetInfo();
    LLVMInitializeAMDGPUTargetInfo();
    LLVMInitializeARMTargetInfo();
    LLVMInitializeAVRTargetInfo();
    LLVMInitializeBPFTargetInfo();
    LLVMInitializeHexagonTargetInfo();
    LLVMInitializeLanaiTargetInfo();
    LLVMInitializeMipsTargetInfo();
    LLVMInitializeMSP430TargetInfo();
    LLVMInitializeNVPTXTargetInfo();
    LLVMInitializePowerPCTargetInfo();
    LLVMInitializeRISCVTargetInfo();
    LLVMInitializeSparcTargetInfo();
    LLVMInitializeSystemZTargetInfo();
    LLVMInitializeWebAssemblyTargetInfo();
    LLVMInitializeX86TargetInfo();
    LLVMInitializeXCoreTargetInfo();
}
pub const initializeAllTargets = LLVMInitializeAllTargets;
fn LLVMInitializeAllTargets() callconv(.C) void {
    LLVMInitializeAArch64Target();
    LLVMInitializeAMDGPUTarget();
    LLVMInitializeARMTarget();
    LLVMInitializeAVRTarget();
    LLVMInitializeBPFTarget();
    LLVMInitializeHexagonTarget();
    LLVMInitializeLanaiTarget();
    LLVMInitializeMipsTarget();
    LLVMInitializeMSP430Target();
    LLVMInitializeNVPTXTarget();
    LLVMInitializePowerPCTarget();
    LLVMInitializeRISCVTarget();
    LLVMInitializeSparcTarget();
    LLVMInitializeSystemZTarget();
    LLVMInitializeWebAssemblyTarget();
    LLVMInitializeX86Target();
    LLVMInitializeXCoreTarget();
}
pub const initializeAllTargetMCs = LLVMInitializeAllTargetMCs;
fn LLVMInitializeAllTargetMCs() callconv(.C) void {
    LLVMInitializeAArch64TargetMC();
    LLVMInitializeAMDGPUTargetMC();
    LLVMInitializeARMTargetMC();
    LLVMInitializeAVRTargetMC();
    LLVMInitializeBPFTargetMC();
    LLVMInitializeHexagonTargetMC();
    LLVMInitializeLanaiTargetMC();
    LLVMInitializeMipsTargetMC();
    LLVMInitializeMSP430TargetMC();
    LLVMInitializeNVPTXTargetMC();
    LLVMInitializePowerPCTargetMC();
    LLVMInitializeRISCVTargetMC();
    LLVMInitializeSparcTargetMC();
    LLVMInitializeSystemZTargetMC();
    LLVMInitializeWebAssemblyTargetMC();
    LLVMInitializeX86TargetMC();
    LLVMInitializeXCoreTargetMC();
}
pub const initializeAllAsmPrinters = LLVMInitializeAllAsmPrinters;
fn LLVMInitializeAllAsmPrinters() callconv(.C) void {
    LLVMInitializeAArch64AsmPrinter();
    LLVMInitializeAMDGPUAsmPrinter();
    LLVMInitializeARMAsmPrinter();
    LLVMInitializeAVRAsmPrinter();
    LLVMInitializeBPFAsmPrinter();
    LLVMInitializeHexagonAsmPrinter();
    LLVMInitializeLanaiAsmPrinter();
    LLVMInitializeMipsAsmPrinter();
    LLVMInitializeMSP430AsmPrinter();
    LLVMInitializeNVPTXAsmPrinter();
    LLVMInitializePowerPCAsmPrinter();
    LLVMInitializeRISCVAsmPrinter();
    LLVMInitializeSparcAsmPrinter();
    LLVMInitializeSystemZAsmPrinter();
    LLVMInitializeWebAssemblyAsmPrinter();
    LLVMInitializeX86AsmPrinter();
    LLVMInitializeXCoreAsmPrinter();
}
pub const initializeAllAsmParsers = LLVMInitializeAllAsmParsers;
fn LLVMInitializeAllAsmParsers() callconv(.C) void {
    LLVMInitializeAArch64AsmParser();
    LLVMInitializeAMDGPUAsmParser();
    LLVMInitializeARMAsmParser();
    LLVMInitializeAVRAsmParser();
    LLVMInitializeBPFAsmParser();
    LLVMInitializeHexagonAsmParser();
    LLVMInitializeLanaiAsmParser();
    LLVMInitializeMipsAsmParser();
    LLVMInitializeMSP430AsmParser();
    LLVMInitializePowerPCAsmParser();
    LLVMInitializeRISCVAsmParser();
    LLVMInitializeSparcAsmParser();
    LLVMInitializeSystemZAsmParser();
    LLVMInitializeWebAssemblyAsmParser();
    LLVMInitializeX86AsmParser();
}

extern fn ZigLLDLinkCOFF(argc: c_int, argv: [*:null]const ?[*:0]const u8, can_exit_early: bool) c_int;
extern fn ZigLLDLinkELF(argc: c_int, argv: [*:null]const ?[*:0]const u8, can_exit_early: bool) c_int;
extern fn ZigLLDLinkWasm(argc: c_int, argv: [*:null]const ?[*:0]const u8, can_exit_early: bool) c_int;

pub const LinkCOFF = ZigLLDLinkCOFF;
pub const LinkELF = ZigLLDLinkELF;
pub const LinkWasm = ZigLLDLinkWasm;

pub const ObjectFormatType = enum(c_int) {
    Unknown,
    COFF,
    ELF,
    GOFF,
    MachO,
    Wasm,
    XCOFF,
};

pub const GetHostCPUName = LLVMGetHostCPUName;
extern fn LLVMGetHostCPUName() ?[*:0]u8;

pub const GetNativeFeatures = ZigLLVMGetNativeFeatures;
extern fn ZigLLVMGetNativeFeatures() ?[*:0]u8;

pub const WriteArchive = ZigLLVMWriteArchive;
extern fn ZigLLVMWriteArchive(
    archive_name: [*:0]const u8,
    file_names_ptr: [*]const [*:0]const u8,
    file_names_len: usize,
    os_type: OSType,
) bool;

pub const OSType = enum(c_int) {
    UnknownOS,
    Ananas,
    CloudABI,
    Darwin,
    DragonFly,
    FreeBSD,
    Fuchsia,
    IOS,
    KFreeBSD,
    Linux,
    Lv2,
    MacOSX,
    NetBSD,
    OpenBSD,
    Solaris,
    Win32,
    ZOS,
    Haiku,
    Minix,
    RTEMS,
    NaCl,
    AIX,
    CUDA,
    NVCL,
    AMDHSA,
    PS4,
    ELFIAMCU,
    TvOS,
    WatchOS,
    Mesa3D,
    Contiki,
    AMDPAL,
    HermitCore,
    Hurd,
    WASI,
    Emscripten,
};

pub const ArchType = enum(c_int) {
    UnknownArch,
    arm,
    armeb,
    aarch64,
    aarch64_be,
    aarch64_32,
    arc,
    avr,
    bpfel,
    bpfeb,
    csky,
    hexagon,
    m68k,
    mips,
    mipsel,
    mips64,
    mips64el,
    msp430,
    ppc,
    ppcle,
    ppc64,
    ppc64le,
    r600,
    amdgcn,
    riscv32,
    riscv64,
    sparc,
    sparcv9,
    sparcel,
    systemz,
    tce,
    tcele,
    thumb,
    thumbeb,
    x86,
    x86_64,
    xcore,
    nvptx,
    nvptx64,
    le32,
    le64,
    amdil,
    amdil64,
    hsail,
    hsail64,
    spir,
    spir64,
    kalimba,
    shave,
    lanai,
    wasm32,
    wasm64,
    renderscript32,
    renderscript64,
    ve,
};

pub const ParseCommandLineOptions = ZigLLVMParseCommandLineOptions;
extern fn ZigLLVMParseCommandLineOptions(argc: usize, argv: [*]const [*:0]const u8) void;

pub const WriteImportLibrary = ZigLLVMWriteImportLibrary;
extern fn ZigLLVMWriteImportLibrary(
    def_path: [*:0]const u8,
    arch: ArchType,
    output_lib_path: [*c]const u8,
    kill_at: bool,
) bool;
