/*
 * Copyright (c) 2019 Andrew Kelley
 *
 * This file is part of zig, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */


/*
 * The point of this file is to contain all the Clang C++ API interaction so that:
 * 1. The compile time of other files is kept under control.
 * 2. Provide a C interface to the Clang functions we need for self-hosting purposes.
 * 3. Prevent C++ from infecting the rest of the project.
 */
#include "zig_clang.h"
#include "clang/AST/OperationKinds.h"

#if __GNUC__ >= 8
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wclass-memaccess"
#endif

#include <clang/Frontend/ASTUnit.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/AST/APValue.h>
#include <clang/AST/Attr.h>
#include <clang/AST/Expr.h>
#include <clang/AST/RecordLayout.h>

#if __GNUC__ >= 8
#pragma GCC diagnostic pop
#endif

// Detect additions to the enum
void ZigClang_detect_enum_BO(clang::BinaryOperatorKind op) {
    switch (op) {
        case clang::BO_PtrMemD:
        case clang::BO_PtrMemI:
        case clang::BO_Cmp:
        case clang::BO_Mul:
        case clang::BO_Div:
        case clang::BO_Rem:
        case clang::BO_Add:
        case clang::BO_Sub:
        case clang::BO_Shl:
        case clang::BO_Shr:
        case clang::BO_LT:
        case clang::BO_GT:
        case clang::BO_LE:
        case clang::BO_GE:
        case clang::BO_EQ:
        case clang::BO_NE:
        case clang::BO_And:
        case clang::BO_Xor:
        case clang::BO_Or:
        case clang::BO_LAnd:
        case clang::BO_LOr:
        case clang::BO_Assign:
        case clang::BO_Comma:
        case clang::BO_MulAssign:
        case clang::BO_DivAssign:
        case clang::BO_RemAssign:
        case clang::BO_AddAssign:
        case clang::BO_SubAssign:
        case clang::BO_ShlAssign:
        case clang::BO_ShrAssign:
        case clang::BO_AndAssign:
        case clang::BO_XorAssign:
        case clang::BO_OrAssign:
            break;
    }
}

static_assert((clang::BinaryOperatorKind)ZigClangBO_Add == clang::BO_Add, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_AddAssign == clang::BO_AddAssign, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_And == clang::BO_And, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_AndAssign == clang::BO_AndAssign, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_Assign == clang::BO_Assign, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_Cmp == clang::BO_Cmp, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_Comma == clang::BO_Comma, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_Div == clang::BO_Div, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_DivAssign == clang::BO_DivAssign, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_EQ == clang::BO_EQ, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_GE == clang::BO_GE, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_GT == clang::BO_GT, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_LAnd == clang::BO_LAnd, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_LE == clang::BO_LE, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_LOr == clang::BO_LOr, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_LT == clang::BO_LT, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_Mul == clang::BO_Mul, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_MulAssign == clang::BO_MulAssign, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_NE == clang::BO_NE, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_Or == clang::BO_Or, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_OrAssign == clang::BO_OrAssign, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_PtrMemD == clang::BO_PtrMemD, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_PtrMemI == clang::BO_PtrMemI, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_Rem == clang::BO_Rem, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_RemAssign == clang::BO_RemAssign, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_Shl == clang::BO_Shl, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_ShlAssign == clang::BO_ShlAssign, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_Shr == clang::BO_Shr, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_ShrAssign == clang::BO_ShrAssign, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_Sub == clang::BO_Sub, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_SubAssign == clang::BO_SubAssign, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_Xor == clang::BO_Xor, "");
static_assert((clang::BinaryOperatorKind)ZigClangBO_XorAssign == clang::BO_XorAssign, "");

// Detect additions to the enum
void ZigClang_detect_enum_UO(clang::UnaryOperatorKind op) {
    switch (op) {
        case clang::UO_AddrOf:
        case clang::UO_Coawait:
        case clang::UO_Deref:
        case clang::UO_Extension:
        case clang::UO_Imag:
        case clang::UO_LNot:
        case clang::UO_Minus:
        case clang::UO_Not:
        case clang::UO_Plus:
        case clang::UO_PostDec:
        case clang::UO_PostInc:
        case clang::UO_PreDec:
        case clang::UO_PreInc:
        case clang::UO_Real:
            break;
    }
}

static_assert((clang::UnaryOperatorKind)ZigClangUO_AddrOf == clang::UO_AddrOf, "");
static_assert((clang::UnaryOperatorKind)ZigClangUO_Coawait == clang::UO_Coawait, "");
static_assert((clang::UnaryOperatorKind)ZigClangUO_Deref == clang::UO_Deref, "");
static_assert((clang::UnaryOperatorKind)ZigClangUO_Extension == clang::UO_Extension, "");
static_assert((clang::UnaryOperatorKind)ZigClangUO_Imag == clang::UO_Imag, "");
static_assert((clang::UnaryOperatorKind)ZigClangUO_LNot == clang::UO_LNot, "");
static_assert((clang::UnaryOperatorKind)ZigClangUO_Minus == clang::UO_Minus, "");
static_assert((clang::UnaryOperatorKind)ZigClangUO_Not == clang::UO_Not, "");
static_assert((clang::UnaryOperatorKind)ZigClangUO_Plus == clang::UO_Plus, "");
static_assert((clang::UnaryOperatorKind)ZigClangUO_PostDec == clang::UO_PostDec, "");
static_assert((clang::UnaryOperatorKind)ZigClangUO_PostInc == clang::UO_PostInc, "");
static_assert((clang::UnaryOperatorKind)ZigClangUO_PreDec == clang::UO_PreDec, "");
static_assert((clang::UnaryOperatorKind)ZigClangUO_PreInc == clang::UO_PreInc, "");
static_assert((clang::UnaryOperatorKind)ZigClangUO_Real == clang::UO_Real, "");

// Detect additions to the enum
void ZigClang_detect_enum_CK(clang::CastKind x) {
    switch (x) {
        case clang::CK_ARCConsumeObject:
        case clang::CK_ARCExtendBlockObject:
        case clang::CK_ARCProduceObject:
        case clang::CK_ARCReclaimReturnedObject:
        case clang::CK_AddressSpaceConversion:
        case clang::CK_AnyPointerToBlockPointerCast:
        case clang::CK_ArrayToPointerDecay:
        case clang::CK_AtomicToNonAtomic:
        case clang::CK_BaseToDerived:
        case clang::CK_BaseToDerivedMemberPointer:
        case clang::CK_BitCast:
        case clang::CK_BlockPointerToObjCPointerCast:
        case clang::CK_BooleanToSignedIntegral:
        case clang::CK_BuiltinFnToFnPtr:
        case clang::CK_CPointerToObjCPointerCast:
        case clang::CK_ConstructorConversion:
        case clang::CK_CopyAndAutoreleaseBlockObject:
        case clang::CK_Dependent:
        case clang::CK_DerivedToBase:
        case clang::CK_DerivedToBaseMemberPointer:
        case clang::CK_Dynamic:
        case clang::CK_FloatingCast:
        case clang::CK_FloatingComplexCast:
        case clang::CK_FloatingComplexToBoolean:
        case clang::CK_FloatingComplexToIntegralComplex:
        case clang::CK_FloatingComplexToReal:
        case clang::CK_FloatingRealToComplex:
        case clang::CK_FloatingToBoolean:
        case clang::CK_FloatingToIntegral:
        case clang::CK_FunctionToPointerDecay:
        case clang::CK_IntToOCLSampler:
        case clang::CK_IntegralCast:
        case clang::CK_IntegralComplexCast:
        case clang::CK_IntegralComplexToBoolean:
        case clang::CK_IntegralComplexToFloatingComplex:
        case clang::CK_IntegralComplexToReal:
        case clang::CK_IntegralRealToComplex:
        case clang::CK_IntegralToBoolean:
        case clang::CK_IntegralToFloating:
        case clang::CK_IntegralToPointer:
        case clang::CK_FloatingToFixedPoint:
        case clang::CK_FixedPointToFloating:
        case clang::CK_LValueBitCast:
        case clang::CK_LValueToRValueBitCast:
        case clang::CK_LValueToRValue:
        case clang::CK_MatrixCast:
        case clang::CK_MemberPointerToBoolean:
        case clang::CK_NoOp:
        case clang::CK_NonAtomicToAtomic:
        case clang::CK_NullToMemberPointer:
        case clang::CK_NullToPointer:
        case clang::CK_ObjCObjectLValueCast:
        case clang::CK_PointerToBoolean:
        case clang::CK_PointerToIntegral:
        case clang::CK_ReinterpretMemberPointer:
        case clang::CK_ToUnion:
        case clang::CK_ToVoid:
        case clang::CK_UncheckedDerivedToBase:
        case clang::CK_UserDefinedConversion:
        case clang::CK_VectorSplat:
        case clang::CK_ZeroToOCLOpaqueType:
        case clang::CK_FixedPointCast:
        case clang::CK_FixedPointToIntegral:
        case clang::CK_IntegralToFixedPoint:
        case clang::CK_FixedPointToBoolean:
            break;
    }
};

static_assert((clang::CastKind)ZigClangCK_Dependent == clang::CK_Dependent, "");
static_assert((clang::CastKind)ZigClangCK_BitCast == clang::CK_BitCast, "");
static_assert((clang::CastKind)ZigClangCK_LValueBitCast == clang::CK_LValueBitCast, "");
static_assert((clang::CastKind)ZigClangCK_LValueToRValueBitCast == clang::CK_LValueToRValueBitCast, "");
static_assert((clang::CastKind)ZigClangCK_LValueToRValue == clang::CK_LValueToRValue, "");
static_assert((clang::CastKind)ZigClangCK_NoOp == clang::CK_NoOp, "");
static_assert((clang::CastKind)ZigClangCK_BaseToDerived == clang::CK_BaseToDerived, "");
static_assert((clang::CastKind)ZigClangCK_DerivedToBase == clang::CK_DerivedToBase, "");
static_assert((clang::CastKind)ZigClangCK_UncheckedDerivedToBase == clang::CK_UncheckedDerivedToBase, "");
static_assert((clang::CastKind)ZigClangCK_Dynamic == clang::CK_Dynamic, "");
static_assert((clang::CastKind)ZigClangCK_ToUnion == clang::CK_ToUnion, "");
static_assert((clang::CastKind)ZigClangCK_ArrayToPointerDecay == clang::CK_ArrayToPointerDecay, "");
static_assert((clang::CastKind)ZigClangCK_FunctionToPointerDecay == clang::CK_FunctionToPointerDecay, "");
static_assert((clang::CastKind)ZigClangCK_NullToPointer == clang::CK_NullToPointer, "");
static_assert((clang::CastKind)ZigClangCK_NullToMemberPointer == clang::CK_NullToMemberPointer, "");
static_assert((clang::CastKind)ZigClangCK_BaseToDerivedMemberPointer == clang::CK_BaseToDerivedMemberPointer, "");
static_assert((clang::CastKind)ZigClangCK_DerivedToBaseMemberPointer == clang::CK_DerivedToBaseMemberPointer, "");
static_assert((clang::CastKind)ZigClangCK_MemberPointerToBoolean == clang::CK_MemberPointerToBoolean, "");
static_assert((clang::CastKind)ZigClangCK_ReinterpretMemberPointer == clang::CK_ReinterpretMemberPointer, "");
static_assert((clang::CastKind)ZigClangCK_UserDefinedConversion == clang::CK_UserDefinedConversion, "");
static_assert((clang::CastKind)ZigClangCK_ConstructorConversion == clang::CK_ConstructorConversion, "");
static_assert((clang::CastKind)ZigClangCK_IntegralToPointer == clang::CK_IntegralToPointer, "");
static_assert((clang::CastKind)ZigClangCK_PointerToIntegral == clang::CK_PointerToIntegral, "");
static_assert((clang::CastKind)ZigClangCK_PointerToBoolean == clang::CK_PointerToBoolean, "");
static_assert((clang::CastKind)ZigClangCK_ToVoid == clang::CK_ToVoid, "");
static_assert((clang::CastKind)ZigClangCK_MatrixCast == clang::CK_MatrixCast, "");
static_assert((clang::CastKind)ZigClangCK_VectorSplat == clang::CK_VectorSplat, "");
static_assert((clang::CastKind)ZigClangCK_IntegralCast == clang::CK_IntegralCast, "");
static_assert((clang::CastKind)ZigClangCK_IntegralToBoolean == clang::CK_IntegralToBoolean, "");
static_assert((clang::CastKind)ZigClangCK_IntegralToFloating == clang::CK_IntegralToFloating, "");
static_assert((clang::CastKind)ZigClangCK_FloatingToFixedPoint == clang::CK_FloatingToFixedPoint, "");
static_assert((clang::CastKind)ZigClangCK_FixedPointToFloating == clang::CK_FixedPointToFloating, "");
static_assert((clang::CastKind)ZigClangCK_FixedPointCast == clang::CK_FixedPointCast, "");
static_assert((clang::CastKind)ZigClangCK_FixedPointToIntegral == clang::CK_FixedPointToIntegral, "");
static_assert((clang::CastKind)ZigClangCK_IntegralToFixedPoint == clang::CK_IntegralToFixedPoint, "");
static_assert((clang::CastKind)ZigClangCK_FixedPointToBoolean == clang::CK_FixedPointToBoolean, "");
static_assert((clang::CastKind)ZigClangCK_FloatingToIntegral == clang::CK_FloatingToIntegral, "");
static_assert((clang::CastKind)ZigClangCK_FloatingToBoolean == clang::CK_FloatingToBoolean, "");
static_assert((clang::CastKind)ZigClangCK_BooleanToSignedIntegral == clang::CK_BooleanToSignedIntegral, "");
static_assert((clang::CastKind)ZigClangCK_FloatingCast == clang::CK_FloatingCast, "");
static_assert((clang::CastKind)ZigClangCK_CPointerToObjCPointerCast == clang::CK_CPointerToObjCPointerCast, "");
static_assert((clang::CastKind)ZigClangCK_BlockPointerToObjCPointerCast == clang::CK_BlockPointerToObjCPointerCast, "");
static_assert((clang::CastKind)ZigClangCK_AnyPointerToBlockPointerCast == clang::CK_AnyPointerToBlockPointerCast, "");
static_assert((clang::CastKind)ZigClangCK_ObjCObjectLValueCast == clang::CK_ObjCObjectLValueCast, "");
static_assert((clang::CastKind)ZigClangCK_FloatingRealToComplex == clang::CK_FloatingRealToComplex, "");
static_assert((clang::CastKind)ZigClangCK_FloatingComplexToReal == clang::CK_FloatingComplexToReal, "");
static_assert((clang::CastKind)ZigClangCK_FloatingComplexToBoolean == clang::CK_FloatingComplexToBoolean, "");
static_assert((clang::CastKind)ZigClangCK_FloatingComplexCast == clang::CK_FloatingComplexCast, "");
static_assert((clang::CastKind)ZigClangCK_FloatingComplexToIntegralComplex == clang::CK_FloatingComplexToIntegralComplex, "");
static_assert((clang::CastKind)ZigClangCK_IntegralRealToComplex == clang::CK_IntegralRealToComplex, "");
static_assert((clang::CastKind)ZigClangCK_IntegralComplexToReal == clang::CK_IntegralComplexToReal, "");
static_assert((clang::CastKind)ZigClangCK_IntegralComplexToBoolean == clang::CK_IntegralComplexToBoolean, "");
static_assert((clang::CastKind)ZigClangCK_IntegralComplexCast == clang::CK_IntegralComplexCast, "");
static_assert((clang::CastKind)ZigClangCK_IntegralComplexToFloatingComplex == clang::CK_IntegralComplexToFloatingComplex, "");
static_assert((clang::CastKind)ZigClangCK_ARCProduceObject == clang::CK_ARCProduceObject, "");
static_assert((clang::CastKind)ZigClangCK_ARCConsumeObject == clang::CK_ARCConsumeObject, "");
static_assert((clang::CastKind)ZigClangCK_ARCReclaimReturnedObject == clang::CK_ARCReclaimReturnedObject, "");
static_assert((clang::CastKind)ZigClangCK_ARCExtendBlockObject == clang::CK_ARCExtendBlockObject, "");
static_assert((clang::CastKind)ZigClangCK_AtomicToNonAtomic == clang::CK_AtomicToNonAtomic, "");
static_assert((clang::CastKind)ZigClangCK_NonAtomicToAtomic == clang::CK_NonAtomicToAtomic, "");
static_assert((clang::CastKind)ZigClangCK_CopyAndAutoreleaseBlockObject == clang::CK_CopyAndAutoreleaseBlockObject, "");
static_assert((clang::CastKind)ZigClangCK_BuiltinFnToFnPtr == clang::CK_BuiltinFnToFnPtr, "");
static_assert((clang::CastKind)ZigClangCK_ZeroToOCLOpaqueType == clang::CK_ZeroToOCLOpaqueType, "");
static_assert((clang::CastKind)ZigClangCK_AddressSpaceConversion == clang::CK_AddressSpaceConversion, "");
static_assert((clang::CastKind)ZigClangCK_IntToOCLSampler == clang::CK_IntToOCLSampler, "");

// Detect additions to the enum
void ZigClang_detect_enum_TypeClass(clang::Type::TypeClass ty) {
    switch (ty) {
        case clang::Type::Builtin:
        case clang::Type::Complex:
        case clang::Type::Pointer:
        case clang::Type::BlockPointer:
        case clang::Type::LValueReference:
        case clang::Type::RValueReference:
        case clang::Type::MemberPointer:
        case clang::Type::ConstantArray:
        case clang::Type::IncompleteArray:
        case clang::Type::VariableArray:
        case clang::Type::DependentSizedArray:
        case clang::Type::DependentSizedExtVector:
        case clang::Type::DependentAddressSpace:
        case clang::Type::DependentExtInt:
        case clang::Type::Vector:
        case clang::Type::DependentVector:
        case clang::Type::ExtVector:
        case clang::Type::FunctionProto:
        case clang::Type::FunctionNoProto:
        case clang::Type::UnresolvedUsing:
        case clang::Type::Paren:
        case clang::Type::Typedef:
        case clang::Type::MacroQualified:
        case clang::Type::ConstantMatrix:
        case clang::Type::DependentSizedMatrix:
        case clang::Type::Adjusted:
        case clang::Type::Decayed:
        case clang::Type::TypeOfExpr:
        case clang::Type::TypeOf:
        case clang::Type::Decltype:
        case clang::Type::UnaryTransform:
        case clang::Type::Record:
        case clang::Type::Enum:
        case clang::Type::Elaborated:
        case clang::Type::ExtInt:
        case clang::Type::Attributed:
        case clang::Type::TemplateTypeParm:
        case clang::Type::SubstTemplateTypeParm:
        case clang::Type::SubstTemplateTypeParmPack:
        case clang::Type::TemplateSpecialization:
        case clang::Type::Auto:
        case clang::Type::DeducedTemplateSpecialization:
        case clang::Type::InjectedClassName:
        case clang::Type::DependentName:
        case clang::Type::DependentTemplateSpecialization:
        case clang::Type::PackExpansion:
        case clang::Type::ObjCTypeParam:
        case clang::Type::ObjCObject:
        case clang::Type::ObjCInterface:
        case clang::Type::ObjCObjectPointer:
        case clang::Type::Pipe:
        case clang::Type::Atomic:
            break;
    }
}

static_assert((clang::Type::TypeClass)ZigClangType_Adjusted == clang::Type::Adjusted, "");
static_assert((clang::Type::TypeClass)ZigClangType_Decayed == clang::Type::Decayed, "");
static_assert((clang::Type::TypeClass)ZigClangType_ConstantArray == clang::Type::ConstantArray, "");
static_assert((clang::Type::TypeClass)ZigClangType_DependentSizedArray == clang::Type::DependentSizedArray, "");
static_assert((clang::Type::TypeClass)ZigClangType_IncompleteArray == clang::Type::IncompleteArray, "");
static_assert((clang::Type::TypeClass)ZigClangType_VariableArray == clang::Type::VariableArray, "");
static_assert((clang::Type::TypeClass)ZigClangType_Atomic == clang::Type::Atomic, "");
static_assert((clang::Type::TypeClass)ZigClangType_Attributed == clang::Type::Attributed, "");
static_assert((clang::Type::TypeClass)ZigClangType_BlockPointer == clang::Type::BlockPointer, "");
static_assert((clang::Type::TypeClass)ZigClangType_Builtin == clang::Type::Builtin, "");
static_assert((clang::Type::TypeClass)ZigClangType_Complex == clang::Type::Complex, "");
static_assert((clang::Type::TypeClass)ZigClangType_Decltype == clang::Type::Decltype, "");
static_assert((clang::Type::TypeClass)ZigClangType_Auto == clang::Type::Auto, "");
static_assert((clang::Type::TypeClass)ZigClangType_DeducedTemplateSpecialization == clang::Type::DeducedTemplateSpecialization, "");
static_assert((clang::Type::TypeClass)ZigClangType_DependentAddressSpace == clang::Type::DependentAddressSpace, "");
static_assert((clang::Type::TypeClass)ZigClangType_DependentExtInt == clang::Type::DependentExtInt, "");
static_assert((clang::Type::TypeClass)ZigClangType_DependentName == clang::Type::DependentName, "");
static_assert((clang::Type::TypeClass)ZigClangType_DependentSizedExtVector == clang::Type::DependentSizedExtVector, "");
static_assert((clang::Type::TypeClass)ZigClangType_DependentTemplateSpecialization == clang::Type::DependentTemplateSpecialization, "");
static_assert((clang::Type::TypeClass)ZigClangType_DependentVector == clang::Type::DependentVector, "");
static_assert((clang::Type::TypeClass)ZigClangType_Elaborated == clang::Type::Elaborated, "");
static_assert((clang::Type::TypeClass)ZigClangType_ExtInt == clang::Type::ExtInt, "");
static_assert((clang::Type::TypeClass)ZigClangType_FunctionNoProto == clang::Type::FunctionNoProto, "");
static_assert((clang::Type::TypeClass)ZigClangType_FunctionProto == clang::Type::FunctionProto, "");
static_assert((clang::Type::TypeClass)ZigClangType_InjectedClassName == clang::Type::InjectedClassName, "");
static_assert((clang::Type::TypeClass)ZigClangType_MacroQualified == clang::Type::MacroQualified, "");
static_assert((clang::Type::TypeClass)ZigClangType_ConstantMatrix == clang::Type::ConstantMatrix, "");
static_assert((clang::Type::TypeClass)ZigClangType_DependentSizedMatrix == clang::Type::DependentSizedMatrix, "");
static_assert((clang::Type::TypeClass)ZigClangType_MemberPointer == clang::Type::MemberPointer, "");
static_assert((clang::Type::TypeClass)ZigClangType_ObjCObjectPointer == clang::Type::ObjCObjectPointer, "");
static_assert((clang::Type::TypeClass)ZigClangType_ObjCObject == clang::Type::ObjCObject, "");
static_assert((clang::Type::TypeClass)ZigClangType_ObjCInterface == clang::Type::ObjCInterface, "");
static_assert((clang::Type::TypeClass)ZigClangType_ObjCTypeParam == clang::Type::ObjCTypeParam, "");
static_assert((clang::Type::TypeClass)ZigClangType_PackExpansion == clang::Type::PackExpansion, "");
static_assert((clang::Type::TypeClass)ZigClangType_Paren == clang::Type::Paren, "");
static_assert((clang::Type::TypeClass)ZigClangType_Pipe == clang::Type::Pipe, "");
static_assert((clang::Type::TypeClass)ZigClangType_Pointer == clang::Type::Pointer, "");
static_assert((clang::Type::TypeClass)ZigClangType_LValueReference == clang::Type::LValueReference, "");
static_assert((clang::Type::TypeClass)ZigClangType_RValueReference == clang::Type::RValueReference, "");
static_assert((clang::Type::TypeClass)ZigClangType_SubstTemplateTypeParmPack == clang::Type::SubstTemplateTypeParmPack, "");
static_assert((clang::Type::TypeClass)ZigClangType_SubstTemplateTypeParm == clang::Type::SubstTemplateTypeParm, "");
static_assert((clang::Type::TypeClass)ZigClangType_Enum == clang::Type::Enum, "");
static_assert((clang::Type::TypeClass)ZigClangType_Record == clang::Type::Record, "");
static_assert((clang::Type::TypeClass)ZigClangType_TemplateSpecialization == clang::Type::TemplateSpecialization, "");
static_assert((clang::Type::TypeClass)ZigClangType_TemplateTypeParm == clang::Type::TemplateTypeParm, "");
static_assert((clang::Type::TypeClass)ZigClangType_TypeOfExpr == clang::Type::TypeOfExpr, "");
static_assert((clang::Type::TypeClass)ZigClangType_TypeOf == clang::Type::TypeOf, "");
static_assert((clang::Type::TypeClass)ZigClangType_Typedef == clang::Type::Typedef, "");
static_assert((clang::Type::TypeClass)ZigClangType_UnaryTransform == clang::Type::UnaryTransform, "");
static_assert((clang::Type::TypeClass)ZigClangType_UnresolvedUsing == clang::Type::UnresolvedUsing, "");
static_assert((clang::Type::TypeClass)ZigClangType_Vector == clang::Type::Vector, "");
static_assert((clang::Type::TypeClass)ZigClangType_ExtVector == clang::Type::ExtVector, "");

// Detect additions to the enum
void ZigClang_detect_enum_StmtClass(clang::Stmt::StmtClass x) {
    switch (static_cast<ZigClangStmtClass>(x)) {
        case ZigClangStmt_NoStmtClass:
        case ZigClangStmt_GCCAsmStmtClass:
        case ZigClangStmt_MSAsmStmtClass:
        case ZigClangStmt_BreakStmtClass:
        case ZigClangStmt_CXXCatchStmtClass:
        case ZigClangStmt_CXXForRangeStmtClass:
        case ZigClangStmt_CXXTryStmtClass:
        case ZigClangStmt_CapturedStmtClass:
        case ZigClangStmt_CompoundStmtClass:
        case ZigClangStmt_ContinueStmtClass:
        case ZigClangStmt_CoreturnStmtClass:
        case ZigClangStmt_CoroutineBodyStmtClass:
        case ZigClangStmt_DeclStmtClass:
        case ZigClangStmt_DoStmtClass:
        case ZigClangStmt_ForStmtClass:
        case ZigClangStmt_GotoStmtClass:
        case ZigClangStmt_IfStmtClass:
        case ZigClangStmt_IndirectGotoStmtClass:
        case ZigClangStmt_MSDependentExistsStmtClass:
        case ZigClangStmt_NullStmtClass:
        case ZigClangStmt_OMPCanonicalLoopClass:
        case ZigClangStmt_OMPAtomicDirectiveClass:
        case ZigClangStmt_OMPBarrierDirectiveClass:
        case ZigClangStmt_OMPCancelDirectiveClass:
        case ZigClangStmt_OMPCancellationPointDirectiveClass:
        case ZigClangStmt_OMPCriticalDirectiveClass:
        case ZigClangStmt_OMPDepobjDirectiveClass:
        case ZigClangStmt_OMPDispatchDirectiveClass:
        case ZigClangStmt_OMPFlushDirectiveClass:
        case ZigClangStmt_OMPInteropDirectiveClass:
        case ZigClangStmt_OMPDistributeDirectiveClass:
        case ZigClangStmt_OMPDistributeParallelForDirectiveClass:
        case ZigClangStmt_OMPDistributeParallelForSimdDirectiveClass:
        case ZigClangStmt_OMPDistributeSimdDirectiveClass:
        case ZigClangStmt_OMPForDirectiveClass:
        case ZigClangStmt_OMPForSimdDirectiveClass:
        case ZigClangStmt_OMPMasterTaskLoopDirectiveClass:
        case ZigClangStmt_OMPMasterTaskLoopSimdDirectiveClass:
        case ZigClangStmt_OMPParallelForDirectiveClass:
        case ZigClangStmt_OMPParallelForSimdDirectiveClass:
        case ZigClangStmt_OMPParallelMasterTaskLoopDirectiveClass:
        case ZigClangStmt_OMPParallelMasterTaskLoopSimdDirectiveClass:
        case ZigClangStmt_OMPSimdDirectiveClass:
        case ZigClangStmt_OMPTargetParallelForSimdDirectiveClass:
        case ZigClangStmt_OMPTargetSimdDirectiveClass:
        case ZigClangStmt_OMPTargetTeamsDistributeDirectiveClass:
        case ZigClangStmt_OMPTargetTeamsDistributeParallelForDirectiveClass:
        case ZigClangStmt_OMPTargetTeamsDistributeParallelForSimdDirectiveClass:
        case ZigClangStmt_OMPTargetTeamsDistributeSimdDirectiveClass:
        case ZigClangStmt_OMPTaskLoopDirectiveClass:
        case ZigClangStmt_OMPTaskLoopSimdDirectiveClass:
        case ZigClangStmt_OMPTeamsDistributeDirectiveClass:
        case ZigClangStmt_OMPTeamsDistributeParallelForDirectiveClass:
        case ZigClangStmt_OMPTeamsDistributeParallelForSimdDirectiveClass:
        case ZigClangStmt_OMPTeamsDistributeSimdDirectiveClass:
        case ZigClangStmt_OMPTileDirectiveClass:
        case ZigClangStmt_OMPUnrollDirectiveClass:
        case ZigClangStmt_OMPMaskedDirectiveClass:
        case ZigClangStmt_OMPMasterDirectiveClass:
        case ZigClangStmt_OMPOrderedDirectiveClass:
        case ZigClangStmt_OMPParallelDirectiveClass:
        case ZigClangStmt_OMPParallelMasterDirectiveClass:
        case ZigClangStmt_OMPParallelSectionsDirectiveClass:
        case ZigClangStmt_OMPScanDirectiveClass:
        case ZigClangStmt_OMPSectionDirectiveClass:
        case ZigClangStmt_OMPSectionsDirectiveClass:
        case ZigClangStmt_OMPSingleDirectiveClass:
        case ZigClangStmt_OMPTargetDataDirectiveClass:
        case ZigClangStmt_OMPTargetDirectiveClass:
        case ZigClangStmt_OMPTargetEnterDataDirectiveClass:
        case ZigClangStmt_OMPTargetExitDataDirectiveClass:
        case ZigClangStmt_OMPTargetParallelDirectiveClass:
        case ZigClangStmt_OMPTargetParallelForDirectiveClass:
        case ZigClangStmt_OMPTargetTeamsDirectiveClass:
        case ZigClangStmt_OMPTargetUpdateDirectiveClass:
        case ZigClangStmt_OMPTaskDirectiveClass:
        case ZigClangStmt_OMPTaskgroupDirectiveClass:
        case ZigClangStmt_OMPTaskwaitDirectiveClass:
        case ZigClangStmt_OMPTaskyieldDirectiveClass:
        case ZigClangStmt_OMPTeamsDirectiveClass:
        case ZigClangStmt_ObjCAtCatchStmtClass:
        case ZigClangStmt_ObjCAtFinallyStmtClass:
        case ZigClangStmt_ObjCAtSynchronizedStmtClass:
        case ZigClangStmt_ObjCAtThrowStmtClass:
        case ZigClangStmt_ObjCAtTryStmtClass:
        case ZigClangStmt_ObjCAutoreleasePoolStmtClass:
        case ZigClangStmt_ObjCForCollectionStmtClass:
        case ZigClangStmt_ReturnStmtClass:
        case ZigClangStmt_SEHExceptStmtClass:
        case ZigClangStmt_SEHFinallyStmtClass:
        case ZigClangStmt_SEHLeaveStmtClass:
        case ZigClangStmt_SEHTryStmtClass:
        case ZigClangStmt_CaseStmtClass:
        case ZigClangStmt_DefaultStmtClass:
        case ZigClangStmt_SwitchStmtClass:
        case ZigClangStmt_AttributedStmtClass:
        case ZigClangStmt_BinaryConditionalOperatorClass:
        case ZigClangStmt_ConditionalOperatorClass:
        case ZigClangStmt_AddrLabelExprClass:
        case ZigClangStmt_ArrayInitIndexExprClass:
        case ZigClangStmt_ArrayInitLoopExprClass:
        case ZigClangStmt_ArraySubscriptExprClass:
        case ZigClangStmt_ArrayTypeTraitExprClass:
        case ZigClangStmt_AsTypeExprClass:
        case ZigClangStmt_AtomicExprClass:
        case ZigClangStmt_BinaryOperatorClass:
        case ZigClangStmt_CompoundAssignOperatorClass:
        case ZigClangStmt_BlockExprClass:
        case ZigClangStmt_CXXBindTemporaryExprClass:
        case ZigClangStmt_CXXBoolLiteralExprClass:
        case ZigClangStmt_CXXConstructExprClass:
        case ZigClangStmt_CXXTemporaryObjectExprClass:
        case ZigClangStmt_CXXDefaultArgExprClass:
        case ZigClangStmt_CXXDefaultInitExprClass:
        case ZigClangStmt_CXXDeleteExprClass:
        case ZigClangStmt_CXXDependentScopeMemberExprClass:
        case ZigClangStmt_CXXFoldExprClass:
        case ZigClangStmt_CXXInheritedCtorInitExprClass:
        case ZigClangStmt_CXXNewExprClass:
        case ZigClangStmt_CXXNoexceptExprClass:
        case ZigClangStmt_CXXNullPtrLiteralExprClass:
        case ZigClangStmt_CXXPseudoDestructorExprClass:
        case ZigClangStmt_CXXRewrittenBinaryOperatorClass:
        case ZigClangStmt_CXXScalarValueInitExprClass:
        case ZigClangStmt_CXXStdInitializerListExprClass:
        case ZigClangStmt_CXXThisExprClass:
        case ZigClangStmt_CXXThrowExprClass:
        case ZigClangStmt_CXXTypeidExprClass:
        case ZigClangStmt_CXXUnresolvedConstructExprClass:
        case ZigClangStmt_CXXUuidofExprClass:
        case ZigClangStmt_CallExprClass:
        case ZigClangStmt_CUDAKernelCallExprClass:
        case ZigClangStmt_CXXMemberCallExprClass:
        case ZigClangStmt_CXXOperatorCallExprClass:
        case ZigClangStmt_UserDefinedLiteralClass:
        case ZigClangStmt_BuiltinBitCastExprClass:
        case ZigClangStmt_CStyleCastExprClass:
        case ZigClangStmt_CXXFunctionalCastExprClass:
        case ZigClangStmt_CXXAddrspaceCastExprClass:
        case ZigClangStmt_CXXConstCastExprClass:
        case ZigClangStmt_CXXDynamicCastExprClass:
        case ZigClangStmt_CXXReinterpretCastExprClass:
        case ZigClangStmt_CXXStaticCastExprClass:
        case ZigClangStmt_ObjCBridgedCastExprClass:
        case ZigClangStmt_ImplicitCastExprClass:
        case ZigClangStmt_CharacterLiteralClass:
        case ZigClangStmt_ChooseExprClass:
        case ZigClangStmt_CompoundLiteralExprClass:
        case ZigClangStmt_ConceptSpecializationExprClass:
        case ZigClangStmt_ConvertVectorExprClass:
        case ZigClangStmt_CoawaitExprClass:
        case ZigClangStmt_CoyieldExprClass:
        case ZigClangStmt_DeclRefExprClass:
        case ZigClangStmt_DependentCoawaitExprClass:
        case ZigClangStmt_DependentScopeDeclRefExprClass:
        case ZigClangStmt_DesignatedInitExprClass:
        case ZigClangStmt_DesignatedInitUpdateExprClass:
        case ZigClangStmt_ExpressionTraitExprClass:
        case ZigClangStmt_ExtVectorElementExprClass:
        case ZigClangStmt_FixedPointLiteralClass:
        case ZigClangStmt_FloatingLiteralClass:
        case ZigClangStmt_ConstantExprClass:
        case ZigClangStmt_ExprWithCleanupsClass:
        case ZigClangStmt_FunctionParmPackExprClass:
        case ZigClangStmt_GNUNullExprClass:
        case ZigClangStmt_GenericSelectionExprClass:
        case ZigClangStmt_ImaginaryLiteralClass:
        case ZigClangStmt_ImplicitValueInitExprClass:
        case ZigClangStmt_InitListExprClass:
        case ZigClangStmt_IntegerLiteralClass:
        case ZigClangStmt_LambdaExprClass:
        case ZigClangStmt_MSPropertyRefExprClass:
        case ZigClangStmt_MSPropertySubscriptExprClass:
        case ZigClangStmt_MaterializeTemporaryExprClass:
        case ZigClangStmt_MatrixSubscriptExprClass:
        case ZigClangStmt_MemberExprClass:
        case ZigClangStmt_NoInitExprClass:
        case ZigClangStmt_OMPArraySectionExprClass:
        case ZigClangStmt_OMPArrayShapingExprClass:
        case ZigClangStmt_OMPIteratorExprClass:
        case ZigClangStmt_ObjCArrayLiteralClass:
        case ZigClangStmt_ObjCAvailabilityCheckExprClass:
        case ZigClangStmt_ObjCBoolLiteralExprClass:
        case ZigClangStmt_ObjCBoxedExprClass:
        case ZigClangStmt_ObjCDictionaryLiteralClass:
        case ZigClangStmt_ObjCEncodeExprClass:
        case ZigClangStmt_ObjCIndirectCopyRestoreExprClass:
        case ZigClangStmt_ObjCIsaExprClass:
        case ZigClangStmt_ObjCIvarRefExprClass:
        case ZigClangStmt_ObjCMessageExprClass:
        case ZigClangStmt_ObjCPropertyRefExprClass:
        case ZigClangStmt_ObjCProtocolExprClass:
        case ZigClangStmt_ObjCSelectorExprClass:
        case ZigClangStmt_ObjCStringLiteralClass:
        case ZigClangStmt_ObjCSubscriptRefExprClass:
        case ZigClangStmt_OffsetOfExprClass:
        case ZigClangStmt_OpaqueValueExprClass:
        case ZigClangStmt_UnresolvedLookupExprClass:
        case ZigClangStmt_UnresolvedMemberExprClass:
        case ZigClangStmt_PackExpansionExprClass:
        case ZigClangStmt_ParenExprClass:
        case ZigClangStmt_ParenListExprClass:
        case ZigClangStmt_PredefinedExprClass:
        case ZigClangStmt_PseudoObjectExprClass:
        case ZigClangStmt_RecoveryExprClass:
        case ZigClangStmt_RequiresExprClass:
        case ZigClangStmt_SYCLUniqueStableNameExprClass:
        case ZigClangStmt_ShuffleVectorExprClass:
        case ZigClangStmt_SizeOfPackExprClass:
        case ZigClangStmt_SourceLocExprClass:
        case ZigClangStmt_StmtExprClass:
        case ZigClangStmt_StringLiteralClass:
        case ZigClangStmt_SubstNonTypeTemplateParmExprClass:
        case ZigClangStmt_SubstNonTypeTemplateParmPackExprClass:
        case ZigClangStmt_TypeTraitExprClass:
        case ZigClangStmt_TypoExprClass:
        case ZigClangStmt_UnaryExprOrTypeTraitExprClass:
        case ZigClangStmt_UnaryOperatorClass:
        case ZigClangStmt_VAArgExprClass:
        case ZigClangStmt_LabelStmtClass:
        case ZigClangStmt_WhileStmtClass:
            break;
    }
}

static_assert((clang::Stmt::StmtClass)ZigClangStmt_NoStmtClass == clang::Stmt::NoStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_GCCAsmStmtClass == clang::Stmt::GCCAsmStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_MSAsmStmtClass == clang::Stmt::MSAsmStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_BreakStmtClass == clang::Stmt::BreakStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXCatchStmtClass == clang::Stmt::CXXCatchStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXForRangeStmtClass == clang::Stmt::CXXForRangeStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXTryStmtClass == clang::Stmt::CXXTryStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CapturedStmtClass == clang::Stmt::CapturedStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CompoundStmtClass == clang::Stmt::CompoundStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ContinueStmtClass == clang::Stmt::ContinueStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CoreturnStmtClass == clang::Stmt::CoreturnStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CoroutineBodyStmtClass == clang::Stmt::CoroutineBodyStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_DeclStmtClass == clang::Stmt::DeclStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_DoStmtClass == clang::Stmt::DoStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ForStmtClass == clang::Stmt::ForStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_GotoStmtClass == clang::Stmt::GotoStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_IfStmtClass == clang::Stmt::IfStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_IndirectGotoStmtClass == clang::Stmt::IndirectGotoStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_MSDependentExistsStmtClass == clang::Stmt::MSDependentExistsStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_NullStmtClass == clang::Stmt::NullStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPCanonicalLoopClass == clang::Stmt::OMPCanonicalLoopClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPAtomicDirectiveClass == clang::Stmt::OMPAtomicDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPBarrierDirectiveClass == clang::Stmt::OMPBarrierDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPCancelDirectiveClass == clang::Stmt::OMPCancelDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPCancellationPointDirectiveClass == clang::Stmt::OMPCancellationPointDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPCriticalDirectiveClass == clang::Stmt::OMPCriticalDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPDepobjDirectiveClass == clang::Stmt::OMPDepobjDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPDispatchDirectiveClass == clang::Stmt::OMPDispatchDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPFlushDirectiveClass == clang::Stmt::OMPFlushDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPInteropDirectiveClass == clang::Stmt::OMPInteropDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPDistributeDirectiveClass == clang::Stmt::OMPDistributeDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPDistributeParallelForDirectiveClass == clang::Stmt::OMPDistributeParallelForDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPDistributeParallelForSimdDirectiveClass == clang::Stmt::OMPDistributeParallelForSimdDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPDistributeSimdDirectiveClass == clang::Stmt::OMPDistributeSimdDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPForDirectiveClass == clang::Stmt::OMPForDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPForSimdDirectiveClass == clang::Stmt::OMPForSimdDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPMasterTaskLoopDirectiveClass == clang::Stmt::OMPMasterTaskLoopDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPMasterTaskLoopSimdDirectiveClass == clang::Stmt::OMPMasterTaskLoopSimdDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPParallelForDirectiveClass == clang::Stmt::OMPParallelForDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPParallelForSimdDirectiveClass == clang::Stmt::OMPParallelForSimdDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPParallelMasterTaskLoopDirectiveClass == clang::Stmt::OMPParallelMasterTaskLoopDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPParallelMasterTaskLoopSimdDirectiveClass == clang::Stmt::OMPParallelMasterTaskLoopSimdDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPSimdDirectiveClass == clang::Stmt::OMPSimdDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTargetParallelForSimdDirectiveClass == clang::Stmt::OMPTargetParallelForSimdDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTargetSimdDirectiveClass == clang::Stmt::OMPTargetSimdDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTargetTeamsDistributeDirectiveClass == clang::Stmt::OMPTargetTeamsDistributeDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTargetTeamsDistributeParallelForDirectiveClass == clang::Stmt::OMPTargetTeamsDistributeParallelForDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTargetTeamsDistributeParallelForSimdDirectiveClass == clang::Stmt::OMPTargetTeamsDistributeParallelForSimdDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTargetTeamsDistributeSimdDirectiveClass == clang::Stmt::OMPTargetTeamsDistributeSimdDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTaskLoopDirectiveClass == clang::Stmt::OMPTaskLoopDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTaskLoopSimdDirectiveClass == clang::Stmt::OMPTaskLoopSimdDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTeamsDistributeDirectiveClass == clang::Stmt::OMPTeamsDistributeDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTeamsDistributeParallelForDirectiveClass == clang::Stmt::OMPTeamsDistributeParallelForDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTeamsDistributeParallelForSimdDirectiveClass == clang::Stmt::OMPTeamsDistributeParallelForSimdDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTeamsDistributeSimdDirectiveClass == clang::Stmt::OMPTeamsDistributeSimdDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTileDirectiveClass == clang::Stmt::OMPTileDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPUnrollDirectiveClass == clang::Stmt::OMPUnrollDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPMaskedDirectiveClass == clang::Stmt::OMPMaskedDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPMasterDirectiveClass == clang::Stmt::OMPMasterDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPOrderedDirectiveClass == clang::Stmt::OMPOrderedDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPParallelDirectiveClass == clang::Stmt::OMPParallelDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPParallelMasterDirectiveClass == clang::Stmt::OMPParallelMasterDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPParallelSectionsDirectiveClass == clang::Stmt::OMPParallelSectionsDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPScanDirectiveClass == clang::Stmt::OMPScanDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPSectionDirectiveClass == clang::Stmt::OMPSectionDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPSectionsDirectiveClass == clang::Stmt::OMPSectionsDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPSingleDirectiveClass == clang::Stmt::OMPSingleDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTargetDataDirectiveClass == clang::Stmt::OMPTargetDataDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTargetDirectiveClass == clang::Stmt::OMPTargetDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTargetEnterDataDirectiveClass == clang::Stmt::OMPTargetEnterDataDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTargetExitDataDirectiveClass == clang::Stmt::OMPTargetExitDataDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTargetParallelDirectiveClass == clang::Stmt::OMPTargetParallelDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTargetParallelForDirectiveClass == clang::Stmt::OMPTargetParallelForDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTargetTeamsDirectiveClass == clang::Stmt::OMPTargetTeamsDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTargetUpdateDirectiveClass == clang::Stmt::OMPTargetUpdateDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTaskDirectiveClass == clang::Stmt::OMPTaskDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTaskgroupDirectiveClass == clang::Stmt::OMPTaskgroupDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTaskwaitDirectiveClass == clang::Stmt::OMPTaskwaitDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTaskyieldDirectiveClass == clang::Stmt::OMPTaskyieldDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPTeamsDirectiveClass == clang::Stmt::OMPTeamsDirectiveClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ObjCAtCatchStmtClass == clang::Stmt::ObjCAtCatchStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ObjCAtFinallyStmtClass == clang::Stmt::ObjCAtFinallyStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ObjCAtSynchronizedStmtClass == clang::Stmt::ObjCAtSynchronizedStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ObjCAtThrowStmtClass == clang::Stmt::ObjCAtThrowStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ObjCAtTryStmtClass == clang::Stmt::ObjCAtTryStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ObjCAutoreleasePoolStmtClass == clang::Stmt::ObjCAutoreleasePoolStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ObjCForCollectionStmtClass == clang::Stmt::ObjCForCollectionStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ReturnStmtClass == clang::Stmt::ReturnStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_SEHExceptStmtClass == clang::Stmt::SEHExceptStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_SEHFinallyStmtClass == clang::Stmt::SEHFinallyStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_SEHLeaveStmtClass == clang::Stmt::SEHLeaveStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_SEHTryStmtClass == clang::Stmt::SEHTryStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CaseStmtClass == clang::Stmt::CaseStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_DefaultStmtClass == clang::Stmt::DefaultStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_SwitchStmtClass == clang::Stmt::SwitchStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_AttributedStmtClass == clang::Stmt::AttributedStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_BinaryConditionalOperatorClass == clang::Stmt::BinaryConditionalOperatorClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ConditionalOperatorClass == clang::Stmt::ConditionalOperatorClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_AddrLabelExprClass == clang::Stmt::AddrLabelExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ArrayInitIndexExprClass == clang::Stmt::ArrayInitIndexExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ArrayInitLoopExprClass == clang::Stmt::ArrayInitLoopExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ArraySubscriptExprClass == clang::Stmt::ArraySubscriptExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ArrayTypeTraitExprClass == clang::Stmt::ArrayTypeTraitExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_AsTypeExprClass == clang::Stmt::AsTypeExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_AtomicExprClass == clang::Stmt::AtomicExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_BinaryOperatorClass == clang::Stmt::BinaryOperatorClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CompoundAssignOperatorClass == clang::Stmt::CompoundAssignOperatorClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_BlockExprClass == clang::Stmt::BlockExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXBindTemporaryExprClass == clang::Stmt::CXXBindTemporaryExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXBoolLiteralExprClass == clang::Stmt::CXXBoolLiteralExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXConstructExprClass == clang::Stmt::CXXConstructExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXTemporaryObjectExprClass == clang::Stmt::CXXTemporaryObjectExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXDefaultArgExprClass == clang::Stmt::CXXDefaultArgExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXDefaultInitExprClass == clang::Stmt::CXXDefaultInitExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXDeleteExprClass == clang::Stmt::CXXDeleteExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXDependentScopeMemberExprClass == clang::Stmt::CXXDependentScopeMemberExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXFoldExprClass == clang::Stmt::CXXFoldExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXInheritedCtorInitExprClass == clang::Stmt::CXXInheritedCtorInitExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXNewExprClass == clang::Stmt::CXXNewExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXNoexceptExprClass == clang::Stmt::CXXNoexceptExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXNullPtrLiteralExprClass == clang::Stmt::CXXNullPtrLiteralExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXPseudoDestructorExprClass == clang::Stmt::CXXPseudoDestructorExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXRewrittenBinaryOperatorClass == clang::Stmt::CXXRewrittenBinaryOperatorClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXScalarValueInitExprClass == clang::Stmt::CXXScalarValueInitExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXStdInitializerListExprClass == clang::Stmt::CXXStdInitializerListExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXThisExprClass == clang::Stmt::CXXThisExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXThrowExprClass == clang::Stmt::CXXThrowExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXTypeidExprClass == clang::Stmt::CXXTypeidExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXUnresolvedConstructExprClass == clang::Stmt::CXXUnresolvedConstructExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXUuidofExprClass == clang::Stmt::CXXUuidofExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CallExprClass == clang::Stmt::CallExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CUDAKernelCallExprClass == clang::Stmt::CUDAKernelCallExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXMemberCallExprClass == clang::Stmt::CXXMemberCallExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXOperatorCallExprClass == clang::Stmt::CXXOperatorCallExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_UserDefinedLiteralClass == clang::Stmt::UserDefinedLiteralClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_BuiltinBitCastExprClass == clang::Stmt::BuiltinBitCastExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CStyleCastExprClass == clang::Stmt::CStyleCastExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXFunctionalCastExprClass == clang::Stmt::CXXFunctionalCastExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXAddrspaceCastExprClass == clang::Stmt::CXXAddrspaceCastExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXConstCastExprClass == clang::Stmt::CXXConstCastExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXDynamicCastExprClass == clang::Stmt::CXXDynamicCastExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXReinterpretCastExprClass == clang::Stmt::CXXReinterpretCastExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CXXStaticCastExprClass == clang::Stmt::CXXStaticCastExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ObjCBridgedCastExprClass == clang::Stmt::ObjCBridgedCastExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ImplicitCastExprClass == clang::Stmt::ImplicitCastExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CharacterLiteralClass == clang::Stmt::CharacterLiteralClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ChooseExprClass == clang::Stmt::ChooseExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CompoundLiteralExprClass == clang::Stmt::CompoundLiteralExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ConceptSpecializationExprClass == clang::Stmt::ConceptSpecializationExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ConvertVectorExprClass == clang::Stmt::ConvertVectorExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CoawaitExprClass == clang::Stmt::CoawaitExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_CoyieldExprClass == clang::Stmt::CoyieldExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_DeclRefExprClass == clang::Stmt::DeclRefExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_DependentCoawaitExprClass == clang::Stmt::DependentCoawaitExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_DependentScopeDeclRefExprClass == clang::Stmt::DependentScopeDeclRefExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_DesignatedInitExprClass == clang::Stmt::DesignatedInitExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_DesignatedInitUpdateExprClass == clang::Stmt::DesignatedInitUpdateExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ExpressionTraitExprClass == clang::Stmt::ExpressionTraitExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ExtVectorElementExprClass == clang::Stmt::ExtVectorElementExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_FixedPointLiteralClass == clang::Stmt::FixedPointLiteralClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_FloatingLiteralClass == clang::Stmt::FloatingLiteralClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ConstantExprClass == clang::Stmt::ConstantExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ExprWithCleanupsClass == clang::Stmt::ExprWithCleanupsClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_FunctionParmPackExprClass == clang::Stmt::FunctionParmPackExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_GNUNullExprClass == clang::Stmt::GNUNullExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_GenericSelectionExprClass == clang::Stmt::GenericSelectionExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ImaginaryLiteralClass == clang::Stmt::ImaginaryLiteralClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ImplicitValueInitExprClass == clang::Stmt::ImplicitValueInitExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_InitListExprClass == clang::Stmt::InitListExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_IntegerLiteralClass == clang::Stmt::IntegerLiteralClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_LambdaExprClass == clang::Stmt::LambdaExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_MSPropertyRefExprClass == clang::Stmt::MSPropertyRefExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_MSPropertySubscriptExprClass == clang::Stmt::MSPropertySubscriptExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_MaterializeTemporaryExprClass == clang::Stmt::MaterializeTemporaryExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_MatrixSubscriptExprClass == clang::Stmt::MatrixSubscriptExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_MemberExprClass == clang::Stmt::MemberExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_NoInitExprClass == clang::Stmt::NoInitExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPArraySectionExprClass == clang::Stmt::OMPArraySectionExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPArrayShapingExprClass == clang::Stmt::OMPArrayShapingExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OMPIteratorExprClass == clang::Stmt::OMPIteratorExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ObjCArrayLiteralClass == clang::Stmt::ObjCArrayLiteralClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ObjCAvailabilityCheckExprClass == clang::Stmt::ObjCAvailabilityCheckExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ObjCBoolLiteralExprClass == clang::Stmt::ObjCBoolLiteralExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ObjCBoxedExprClass == clang::Stmt::ObjCBoxedExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ObjCDictionaryLiteralClass == clang::Stmt::ObjCDictionaryLiteralClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ObjCEncodeExprClass == clang::Stmt::ObjCEncodeExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ObjCIndirectCopyRestoreExprClass == clang::Stmt::ObjCIndirectCopyRestoreExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ObjCIsaExprClass == clang::Stmt::ObjCIsaExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ObjCIvarRefExprClass == clang::Stmt::ObjCIvarRefExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ObjCMessageExprClass == clang::Stmt::ObjCMessageExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ObjCPropertyRefExprClass == clang::Stmt::ObjCPropertyRefExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ObjCProtocolExprClass == clang::Stmt::ObjCProtocolExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ObjCSelectorExprClass == clang::Stmt::ObjCSelectorExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ObjCStringLiteralClass == clang::Stmt::ObjCStringLiteralClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ObjCSubscriptRefExprClass == clang::Stmt::ObjCSubscriptRefExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OffsetOfExprClass == clang::Stmt::OffsetOfExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_OpaqueValueExprClass == clang::Stmt::OpaqueValueExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_UnresolvedLookupExprClass == clang::Stmt::UnresolvedLookupExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_UnresolvedMemberExprClass == clang::Stmt::UnresolvedMemberExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_PackExpansionExprClass == clang::Stmt::PackExpansionExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ParenExprClass == clang::Stmt::ParenExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ParenListExprClass == clang::Stmt::ParenListExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_PredefinedExprClass == clang::Stmt::PredefinedExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_PseudoObjectExprClass == clang::Stmt::PseudoObjectExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_RecoveryExprClass == clang::Stmt::RecoveryExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_RequiresExprClass == clang::Stmt::RequiresExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_SYCLUniqueStableNameExprClass == clang::Stmt::SYCLUniqueStableNameExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_ShuffleVectorExprClass == clang::Stmt::ShuffleVectorExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_SizeOfPackExprClass == clang::Stmt::SizeOfPackExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_SourceLocExprClass == clang::Stmt::SourceLocExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_StmtExprClass == clang::Stmt::StmtExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_StringLiteralClass == clang::Stmt::StringLiteralClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_SubstNonTypeTemplateParmExprClass == clang::Stmt::SubstNonTypeTemplateParmExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_SubstNonTypeTemplateParmPackExprClass == clang::Stmt::SubstNonTypeTemplateParmPackExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_TypeTraitExprClass == clang::Stmt::TypeTraitExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_TypoExprClass == clang::Stmt::TypoExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_UnaryExprOrTypeTraitExprClass == clang::Stmt::UnaryExprOrTypeTraitExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_UnaryOperatorClass == clang::Stmt::UnaryOperatorClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_VAArgExprClass == clang::Stmt::VAArgExprClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_LabelStmtClass == clang::Stmt::LabelStmtClass, "");
static_assert((clang::Stmt::StmtClass)ZigClangStmt_WhileStmtClass == clang::Stmt::WhileStmtClass, "");


void ZigClang_detect_enum_APValueKind(clang::APValue::ValueKind x) {
    switch (x) {
        case clang::APValue::None:
        case clang::APValue::Indeterminate:
        case clang::APValue::Int:
        case clang::APValue::Float:
        case clang::APValue::FixedPoint:
        case clang::APValue::ComplexInt:
        case clang::APValue::ComplexFloat:
        case clang::APValue::LValue:
        case clang::APValue::Vector:
        case clang::APValue::Array:
        case clang::APValue::Struct:
        case clang::APValue::Union:
        case clang::APValue::MemberPointer:
        case clang::APValue::AddrLabelDiff:
            break;
    }
}

static_assert((clang::APValue::ValueKind)ZigClangAPValueNone == clang::APValue::None, "");
static_assert((clang::APValue::ValueKind)ZigClangAPValueIndeterminate == clang::APValue::Indeterminate, "");
static_assert((clang::APValue::ValueKind)ZigClangAPValueInt == clang::APValue::Int, "");
static_assert((clang::APValue::ValueKind)ZigClangAPValueFloat == clang::APValue::Float, "");
static_assert((clang::APValue::ValueKind)ZigClangAPValueFixedPoint == clang::APValue::FixedPoint, "");
static_assert((clang::APValue::ValueKind)ZigClangAPValueComplexInt == clang::APValue::ComplexInt, "");
static_assert((clang::APValue::ValueKind)ZigClangAPValueComplexFloat == clang::APValue::ComplexFloat, "");
static_assert((clang::APValue::ValueKind)ZigClangAPValueLValue == clang::APValue::LValue, "");
static_assert((clang::APValue::ValueKind)ZigClangAPValueVector == clang::APValue::Vector, "");
static_assert((clang::APValue::ValueKind)ZigClangAPValueArray == clang::APValue::Array, "");
static_assert((clang::APValue::ValueKind)ZigClangAPValueStruct == clang::APValue::Struct, "");
static_assert((clang::APValue::ValueKind)ZigClangAPValueUnion == clang::APValue::Union, "");
static_assert((clang::APValue::ValueKind)ZigClangAPValueMemberPointer == clang::APValue::MemberPointer, "");
static_assert((clang::APValue::ValueKind)ZigClangAPValueAddrLabelDiff == clang::APValue::AddrLabelDiff, "");


void ZigClang_detect_enum_DeclKind(clang::Decl::Kind x) {
    switch (x) {
        case clang::Decl::AccessSpec:
        case clang::Decl::Block:
        case clang::Decl::Captured:
        case clang::Decl::ClassScopeFunctionSpecialization:
        case clang::Decl::Empty:
        case clang::Decl::Export:
        case clang::Decl::ExternCContext:
        case clang::Decl::FileScopeAsm:
        case clang::Decl::Friend:
        case clang::Decl::FriendTemplate:
        case clang::Decl::Import:
        case clang::Decl::LifetimeExtendedTemporary:
        case clang::Decl::LinkageSpec:
        case clang::Decl::Using:
        case clang::Decl::UsingEnum:
        case clang::Decl::Label:
        case clang::Decl::Namespace:
        case clang::Decl::NamespaceAlias:
        case clang::Decl::ObjCCompatibleAlias:
        case clang::Decl::ObjCCategory:
        case clang::Decl::ObjCCategoryImpl:
        case clang::Decl::ObjCImplementation:
        case clang::Decl::ObjCInterface:
        case clang::Decl::ObjCProtocol:
        case clang::Decl::ObjCMethod:
        case clang::Decl::ObjCProperty:
        case clang::Decl::BuiltinTemplate:
        case clang::Decl::Concept:
        case clang::Decl::ClassTemplate:
        case clang::Decl::FunctionTemplate:
        case clang::Decl::TypeAliasTemplate:
        case clang::Decl::VarTemplate:
        case clang::Decl::TemplateTemplateParm:
        case clang::Decl::Enum:
        case clang::Decl::Record:
        case clang::Decl::CXXRecord:
        case clang::Decl::ClassTemplateSpecialization:
        case clang::Decl::ClassTemplatePartialSpecialization:
        case clang::Decl::TemplateTypeParm:
        case clang::Decl::ObjCTypeParam:
        case clang::Decl::TypeAlias:
        case clang::Decl::Typedef:
        case clang::Decl::UnresolvedUsingTypename:
        case clang::Decl::UnresolvedUsingIfExists:
        case clang::Decl::UsingDirective:
        case clang::Decl::UsingPack:
        case clang::Decl::UsingShadow:
        case clang::Decl::ConstructorUsingShadow:
        case clang::Decl::Binding:
        case clang::Decl::Field:
        case clang::Decl::ObjCAtDefsField:
        case clang::Decl::ObjCIvar:
        case clang::Decl::Function:
        case clang::Decl::CXXDeductionGuide:
        case clang::Decl::CXXMethod:
        case clang::Decl::CXXConstructor:
        case clang::Decl::CXXConversion:
        case clang::Decl::CXXDestructor:
        case clang::Decl::MSProperty:
        case clang::Decl::NonTypeTemplateParm:
        case clang::Decl::Var:
        case clang::Decl::Decomposition:
        case clang::Decl::ImplicitParam:
        case clang::Decl::OMPCapturedExpr:
        case clang::Decl::ParmVar:
        case clang::Decl::VarTemplateSpecialization:
        case clang::Decl::VarTemplatePartialSpecialization:
        case clang::Decl::EnumConstant:
        case clang::Decl::IndirectField:
        case clang::Decl::MSGuid:
        case clang::Decl::OMPDeclareMapper:
        case clang::Decl::OMPDeclareReduction:
        case clang::Decl::TemplateParamObject:
        case clang::Decl::UnresolvedUsingValue:
        case clang::Decl::OMPAllocate:
        case clang::Decl::OMPRequires:
        case clang::Decl::OMPThreadPrivate:
        case clang::Decl::ObjCPropertyImpl:
        case clang::Decl::PragmaComment:
        case clang::Decl::PragmaDetectMismatch:
        case clang::Decl::RequiresExprBody:
        case clang::Decl::StaticAssert:
        case clang::Decl::TranslationUnit:
            break;
    }
}

static_assert((clang::Decl::Kind)ZigClangDeclAccessSpec == clang::Decl::AccessSpec, "");
static_assert((clang::Decl::Kind)ZigClangDeclBlock == clang::Decl::Block, "");
static_assert((clang::Decl::Kind)ZigClangDeclCaptured == clang::Decl::Captured, "");
static_assert((clang::Decl::Kind)ZigClangDeclClassScopeFunctionSpecialization == clang::Decl::ClassScopeFunctionSpecialization, "");
static_assert((clang::Decl::Kind)ZigClangDeclEmpty == clang::Decl::Empty, "");
static_assert((clang::Decl::Kind)ZigClangDeclExport == clang::Decl::Export, "");
static_assert((clang::Decl::Kind)ZigClangDeclExternCContext == clang::Decl::ExternCContext, "");
static_assert((clang::Decl::Kind)ZigClangDeclFileScopeAsm == clang::Decl::FileScopeAsm, "");
static_assert((clang::Decl::Kind)ZigClangDeclFriend == clang::Decl::Friend, "");
static_assert((clang::Decl::Kind)ZigClangDeclFriendTemplate == clang::Decl::FriendTemplate, "");
static_assert((clang::Decl::Kind)ZigClangDeclImport == clang::Decl::Import, "");
static_assert((clang::Decl::Kind)ZigClangDeclLifetimeExtendedTemporary == clang::Decl::LifetimeExtendedTemporary, "");
static_assert((clang::Decl::Kind)ZigClangDeclLinkageSpec == clang::Decl::LinkageSpec, "");
static_assert((clang::Decl::Kind)ZigClangDeclUsing == clang::Decl::Using, "");
static_assert((clang::Decl::Kind)ZigClangDeclUsingEnum == clang::Decl::UsingEnum, "");
static_assert((clang::Decl::Kind)ZigClangDeclLabel == clang::Decl::Label, "");
static_assert((clang::Decl::Kind)ZigClangDeclNamespace == clang::Decl::Namespace, "");
static_assert((clang::Decl::Kind)ZigClangDeclNamespaceAlias == clang::Decl::NamespaceAlias, "");
static_assert((clang::Decl::Kind)ZigClangDeclObjCCompatibleAlias == clang::Decl::ObjCCompatibleAlias, "");
static_assert((clang::Decl::Kind)ZigClangDeclObjCCategory == clang::Decl::ObjCCategory, "");
static_assert((clang::Decl::Kind)ZigClangDeclObjCCategoryImpl == clang::Decl::ObjCCategoryImpl, "");
static_assert((clang::Decl::Kind)ZigClangDeclObjCImplementation == clang::Decl::ObjCImplementation, "");
static_assert((clang::Decl::Kind)ZigClangDeclObjCInterface == clang::Decl::ObjCInterface, "");
static_assert((clang::Decl::Kind)ZigClangDeclObjCProtocol == clang::Decl::ObjCProtocol, "");
static_assert((clang::Decl::Kind)ZigClangDeclObjCMethod == clang::Decl::ObjCMethod, "");
static_assert((clang::Decl::Kind)ZigClangDeclObjCProperty == clang::Decl::ObjCProperty, "");
static_assert((clang::Decl::Kind)ZigClangDeclBuiltinTemplate == clang::Decl::BuiltinTemplate, "");
static_assert((clang::Decl::Kind)ZigClangDeclConcept == clang::Decl::Concept, "");
static_assert((clang::Decl::Kind)ZigClangDeclClassTemplate == clang::Decl::ClassTemplate, "");
static_assert((clang::Decl::Kind)ZigClangDeclFunctionTemplate == clang::Decl::FunctionTemplate, "");
static_assert((clang::Decl::Kind)ZigClangDeclTypeAliasTemplate == clang::Decl::TypeAliasTemplate, "");
static_assert((clang::Decl::Kind)ZigClangDeclVarTemplate == clang::Decl::VarTemplate, "");
static_assert((clang::Decl::Kind)ZigClangDeclTemplateTemplateParm == clang::Decl::TemplateTemplateParm, "");
static_assert((clang::Decl::Kind)ZigClangDeclEnum == clang::Decl::Enum, "");
static_assert((clang::Decl::Kind)ZigClangDeclRecord == clang::Decl::Record, "");
static_assert((clang::Decl::Kind)ZigClangDeclCXXRecord == clang::Decl::CXXRecord, "");
static_assert((clang::Decl::Kind)ZigClangDeclClassTemplateSpecialization == clang::Decl::ClassTemplateSpecialization, "");
static_assert((clang::Decl::Kind)ZigClangDeclClassTemplatePartialSpecialization == clang::Decl::ClassTemplatePartialSpecialization, "");
static_assert((clang::Decl::Kind)ZigClangDeclTemplateTypeParm == clang::Decl::TemplateTypeParm, "");
static_assert((clang::Decl::Kind)ZigClangDeclObjCTypeParam == clang::Decl::ObjCTypeParam, "");
static_assert((clang::Decl::Kind)ZigClangDeclTypeAlias == clang::Decl::TypeAlias, "");
static_assert((clang::Decl::Kind)ZigClangDeclTypedef == clang::Decl::Typedef, "");
static_assert((clang::Decl::Kind)ZigClangDeclUnresolvedUsingTypename == clang::Decl::UnresolvedUsingTypename, "");
static_assert((clang::Decl::Kind)ZigClangDeclUnresolvedUsingIfExists == clang::Decl::UnresolvedUsingIfExists, "");
static_assert((clang::Decl::Kind)ZigClangDeclOMPAllocate == clang::Decl::OMPAllocate, "");
static_assert((clang::Decl::Kind)ZigClangDeclUsingDirective == clang::Decl::UsingDirective, "");
static_assert((clang::Decl::Kind)ZigClangDeclUsingPack == clang::Decl::UsingPack, "");
static_assert((clang::Decl::Kind)ZigClangDeclUsingShadow == clang::Decl::UsingShadow, "");
static_assert((clang::Decl::Kind)ZigClangDeclConstructorUsingShadow == clang::Decl::ConstructorUsingShadow, "");
static_assert((clang::Decl::Kind)ZigClangDeclBinding == clang::Decl::Binding, "");
static_assert((clang::Decl::Kind)ZigClangDeclField == clang::Decl::Field, "");
static_assert((clang::Decl::Kind)ZigClangDeclObjCAtDefsField == clang::Decl::ObjCAtDefsField, "");
static_assert((clang::Decl::Kind)ZigClangDeclObjCIvar == clang::Decl::ObjCIvar, "");
static_assert((clang::Decl::Kind)ZigClangDeclFunction == clang::Decl::Function, "");
static_assert((clang::Decl::Kind)ZigClangDeclCXXDeductionGuide == clang::Decl::CXXDeductionGuide, "");
static_assert((clang::Decl::Kind)ZigClangDeclCXXMethod == clang::Decl::CXXMethod, "");
static_assert((clang::Decl::Kind)ZigClangDeclCXXConstructor == clang::Decl::CXXConstructor, "");
static_assert((clang::Decl::Kind)ZigClangDeclCXXConversion == clang::Decl::CXXConversion, "");
static_assert((clang::Decl::Kind)ZigClangDeclCXXDestructor == clang::Decl::CXXDestructor, "");
static_assert((clang::Decl::Kind)ZigClangDeclMSProperty == clang::Decl::MSProperty, "");
static_assert((clang::Decl::Kind)ZigClangDeclNonTypeTemplateParm == clang::Decl::NonTypeTemplateParm, "");
static_assert((clang::Decl::Kind)ZigClangDeclVar == clang::Decl::Var, "");
static_assert((clang::Decl::Kind)ZigClangDeclDecomposition == clang::Decl::Decomposition, "");
static_assert((clang::Decl::Kind)ZigClangDeclImplicitParam == clang::Decl::ImplicitParam, "");
static_assert((clang::Decl::Kind)ZigClangDeclOMPCapturedExpr == clang::Decl::OMPCapturedExpr, "");
static_assert((clang::Decl::Kind)ZigClangDeclParmVar == clang::Decl::ParmVar, "");
static_assert((clang::Decl::Kind)ZigClangDeclVarTemplateSpecialization == clang::Decl::VarTemplateSpecialization, "");
static_assert((clang::Decl::Kind)ZigClangDeclVarTemplatePartialSpecialization == clang::Decl::VarTemplatePartialSpecialization, "");
static_assert((clang::Decl::Kind)ZigClangDeclEnumConstant == clang::Decl::EnumConstant, "");
static_assert((clang::Decl::Kind)ZigClangDeclIndirectField == clang::Decl::IndirectField, "");
static_assert((clang::Decl::Kind)ZigClangDeclMSGuid == clang::Decl::MSGuid, "");
static_assert((clang::Decl::Kind)ZigClangDeclOMPDeclareMapper == clang::Decl::OMPDeclareMapper, "");
static_assert((clang::Decl::Kind)ZigClangDeclOMPDeclareReduction == clang::Decl::OMPDeclareReduction, "");
static_assert((clang::Decl::Kind)ZigClangDeclTemplateParamObject == clang::Decl::TemplateParamObject, "");
static_assert((clang::Decl::Kind)ZigClangDeclUnresolvedUsingValue == clang::Decl::UnresolvedUsingValue, "");
static_assert((clang::Decl::Kind)ZigClangDeclOMPRequires == clang::Decl::OMPRequires, "");
static_assert((clang::Decl::Kind)ZigClangDeclOMPThreadPrivate == clang::Decl::OMPThreadPrivate, "");
static_assert((clang::Decl::Kind)ZigClangDeclObjCPropertyImpl == clang::Decl::ObjCPropertyImpl, "");
static_assert((clang::Decl::Kind)ZigClangDeclPragmaComment == clang::Decl::PragmaComment, "");
static_assert((clang::Decl::Kind)ZigClangDeclPragmaDetectMismatch == clang::Decl::PragmaDetectMismatch, "");
static_assert((clang::Decl::Kind)ZigClangDeclRequiresExprBody == clang::Decl::RequiresExprBody, "");
static_assert((clang::Decl::Kind)ZigClangDeclStaticAssert == clang::Decl::StaticAssert, "");
static_assert((clang::Decl::Kind)ZigClangDeclTranslationUnit == clang::Decl::TranslationUnit, "");

void ZigClang_detect_enum_BuiltinTypeKind(clang::BuiltinType::Kind x) {
    switch (x) {
        case clang::BuiltinType::OCLImage1dRO:
        case clang::BuiltinType::OCLImage1dArrayRO:
        case clang::BuiltinType::OCLImage1dBufferRO:
        case clang::BuiltinType::OCLImage2dRO:
        case clang::BuiltinType::OCLImage2dArrayRO:
        case clang::BuiltinType::OCLImage2dDepthRO:
        case clang::BuiltinType::OCLImage2dArrayDepthRO:
        case clang::BuiltinType::OCLImage2dMSAARO:
        case clang::BuiltinType::OCLImage2dArrayMSAARO:
        case clang::BuiltinType::OCLImage2dMSAADepthRO:
        case clang::BuiltinType::OCLImage2dArrayMSAADepthRO:
        case clang::BuiltinType::OCLImage3dRO:
        case clang::BuiltinType::OCLImage1dWO:
        case clang::BuiltinType::OCLImage1dArrayWO:
        case clang::BuiltinType::OCLImage1dBufferWO:
        case clang::BuiltinType::OCLImage2dWO:
        case clang::BuiltinType::OCLImage2dArrayWO:
        case clang::BuiltinType::OCLImage2dDepthWO:
        case clang::BuiltinType::OCLImage2dArrayDepthWO:
        case clang::BuiltinType::OCLImage2dMSAAWO:
        case clang::BuiltinType::OCLImage2dArrayMSAAWO:
        case clang::BuiltinType::OCLImage2dMSAADepthWO:
        case clang::BuiltinType::OCLImage2dArrayMSAADepthWO:
        case clang::BuiltinType::OCLImage3dWO:
        case clang::BuiltinType::OCLImage1dRW:
        case clang::BuiltinType::OCLImage1dArrayRW:
        case clang::BuiltinType::OCLImage1dBufferRW:
        case clang::BuiltinType::OCLImage2dRW:
        case clang::BuiltinType::OCLImage2dArrayRW:
        case clang::BuiltinType::OCLImage2dDepthRW:
        case clang::BuiltinType::OCLImage2dArrayDepthRW:
        case clang::BuiltinType::OCLImage2dMSAARW:
        case clang::BuiltinType::OCLImage2dArrayMSAARW:
        case clang::BuiltinType::OCLImage2dMSAADepthRW:
        case clang::BuiltinType::OCLImage2dArrayMSAADepthRW:
        case clang::BuiltinType::OCLImage3dRW:
        case clang::BuiltinType::OCLIntelSubgroupAVCMcePayload:
        case clang::BuiltinType::OCLIntelSubgroupAVCImePayload:
        case clang::BuiltinType::OCLIntelSubgroupAVCRefPayload:
        case clang::BuiltinType::OCLIntelSubgroupAVCSicPayload:
        case clang::BuiltinType::OCLIntelSubgroupAVCMceResult:
        case clang::BuiltinType::OCLIntelSubgroupAVCImeResult:
        case clang::BuiltinType::OCLIntelSubgroupAVCRefResult:
        case clang::BuiltinType::OCLIntelSubgroupAVCSicResult:
        case clang::BuiltinType::OCLIntelSubgroupAVCImeResultSingleRefStreamout:
        case clang::BuiltinType::OCLIntelSubgroupAVCImeResultDualRefStreamout:
        case clang::BuiltinType::OCLIntelSubgroupAVCImeSingleRefStreamin:
        case clang::BuiltinType::OCLIntelSubgroupAVCImeDualRefStreamin:
        case clang::BuiltinType::SveInt8:
        case clang::BuiltinType::SveInt16:
        case clang::BuiltinType::SveInt32:
        case clang::BuiltinType::SveInt64:
        case clang::BuiltinType::SveUint8:
        case clang::BuiltinType::SveUint16:
        case clang::BuiltinType::SveUint32:
        case clang::BuiltinType::SveUint64:
        case clang::BuiltinType::SveFloat16:
        case clang::BuiltinType::SveFloat32:
        case clang::BuiltinType::SveFloat64:
        case clang::BuiltinType::SveBFloat16:
        case clang::BuiltinType::SveInt8x2:
        case clang::BuiltinType::SveInt16x2:
        case clang::BuiltinType::SveInt32x2:
        case clang::BuiltinType::SveInt64x2:
        case clang::BuiltinType::SveUint8x2:
        case clang::BuiltinType::SveUint16x2:
        case clang::BuiltinType::SveUint32x2:
        case clang::BuiltinType::SveUint64x2:
        case clang::BuiltinType::SveFloat16x2:
        case clang::BuiltinType::SveFloat32x2:
        case clang::BuiltinType::SveFloat64x2:
        case clang::BuiltinType::SveBFloat16x2:
        case clang::BuiltinType::SveInt8x3:
        case clang::BuiltinType::SveInt16x3:
        case clang::BuiltinType::SveInt32x3:
        case clang::BuiltinType::SveInt64x3:
        case clang::BuiltinType::SveUint8x3:
        case clang::BuiltinType::SveUint16x3:
        case clang::BuiltinType::SveUint32x3:
        case clang::BuiltinType::SveUint64x3:
        case clang::BuiltinType::SveFloat16x3:
        case clang::BuiltinType::SveFloat32x3:
        case clang::BuiltinType::SveFloat64x3:
        case clang::BuiltinType::SveBFloat16x3:
        case clang::BuiltinType::SveInt8x4:
        case clang::BuiltinType::SveInt16x4:
        case clang::BuiltinType::SveInt32x4:
        case clang::BuiltinType::SveInt64x4:
        case clang::BuiltinType::SveUint8x4:
        case clang::BuiltinType::SveUint16x4:
        case clang::BuiltinType::SveUint32x4:
        case clang::BuiltinType::SveUint64x4:
        case clang::BuiltinType::SveFloat16x4:
        case clang::BuiltinType::SveFloat32x4:
        case clang::BuiltinType::SveFloat64x4:
        case clang::BuiltinType::SveBFloat16x4:
        case clang::BuiltinType::SveBool:
        case clang::BuiltinType::VectorQuad:
        case clang::BuiltinType::VectorPair:
        case clang::BuiltinType::RvvInt8mf8:
        case clang::BuiltinType::RvvInt8mf4:
        case clang::BuiltinType::RvvInt8mf2:
        case clang::BuiltinType::RvvInt8m1:
        case clang::BuiltinType::RvvInt8m2:
        case clang::BuiltinType::RvvInt8m4:
        case clang::BuiltinType::RvvInt8m8:
        case clang::BuiltinType::RvvUint8mf8:
        case clang::BuiltinType::RvvUint8mf4:
        case clang::BuiltinType::RvvUint8mf2:
        case clang::BuiltinType::RvvUint8m1:
        case clang::BuiltinType::RvvUint8m2:
        case clang::BuiltinType::RvvUint8m4:
        case clang::BuiltinType::RvvUint8m8:
        case clang::BuiltinType::RvvInt16mf4:
        case clang::BuiltinType::RvvInt16mf2:
        case clang::BuiltinType::RvvInt16m1:
        case clang::BuiltinType::RvvInt16m2:
        case clang::BuiltinType::RvvInt16m4:
        case clang::BuiltinType::RvvInt16m8:
        case clang::BuiltinType::RvvUint16mf4:
        case clang::BuiltinType::RvvUint16mf2:
        case clang::BuiltinType::RvvUint16m1:
        case clang::BuiltinType::RvvUint16m2:
        case clang::BuiltinType::RvvUint16m4:
        case clang::BuiltinType::RvvUint16m8:
        case clang::BuiltinType::RvvInt32mf2:
        case clang::BuiltinType::RvvInt32m1:
        case clang::BuiltinType::RvvInt32m2:
        case clang::BuiltinType::RvvInt32m4:
        case clang::BuiltinType::RvvInt32m8:
        case clang::BuiltinType::RvvUint32mf2:
        case clang::BuiltinType::RvvUint32m1:
        case clang::BuiltinType::RvvUint32m2:
        case clang::BuiltinType::RvvUint32m4:
        case clang::BuiltinType::RvvUint32m8:
        case clang::BuiltinType::RvvInt64m1:
        case clang::BuiltinType::RvvInt64m2:
        case clang::BuiltinType::RvvInt64m4:
        case clang::BuiltinType::RvvInt64m8:
        case clang::BuiltinType::RvvUint64m1:
        case clang::BuiltinType::RvvUint64m2:
        case clang::BuiltinType::RvvUint64m4:
        case clang::BuiltinType::RvvUint64m8:
        case clang::BuiltinType::RvvFloat16mf4:
        case clang::BuiltinType::RvvFloat16mf2:
        case clang::BuiltinType::RvvFloat16m1:
        case clang::BuiltinType::RvvFloat16m2:
        case clang::BuiltinType::RvvFloat16m4:
        case clang::BuiltinType::RvvFloat16m8:
        case clang::BuiltinType::RvvFloat32mf2:
        case clang::BuiltinType::RvvFloat32m1:
        case clang::BuiltinType::RvvFloat32m2:
        case clang::BuiltinType::RvvFloat32m4:
        case clang::BuiltinType::RvvFloat32m8:
        case clang::BuiltinType::RvvFloat64m1:
        case clang::BuiltinType::RvvFloat64m2:
        case clang::BuiltinType::RvvFloat64m4:
        case clang::BuiltinType::RvvFloat64m8:
        case clang::BuiltinType::RvvBool1:
        case clang::BuiltinType::RvvBool2:
        case clang::BuiltinType::RvvBool4:
        case clang::BuiltinType::RvvBool8:
        case clang::BuiltinType::RvvBool16:
        case clang::BuiltinType::RvvBool32:
        case clang::BuiltinType::RvvBool64:
        case clang::BuiltinType::Void:
        case clang::BuiltinType::Bool:
        case clang::BuiltinType::Char_U:
        case clang::BuiltinType::UChar:
        case clang::BuiltinType::WChar_U:
        case clang::BuiltinType::Char8:
        case clang::BuiltinType::Char16:
        case clang::BuiltinType::Char32:
        case clang::BuiltinType::UShort:
        case clang::BuiltinType::UInt:
        case clang::BuiltinType::ULong:
        case clang::BuiltinType::ULongLong:
        case clang::BuiltinType::UInt128:
        case clang::BuiltinType::Char_S:
        case clang::BuiltinType::SChar:
        case clang::BuiltinType::WChar_S:
        case clang::BuiltinType::Short:
        case clang::BuiltinType::Int:
        case clang::BuiltinType::Long:
        case clang::BuiltinType::LongLong:
        case clang::BuiltinType::Int128:
        case clang::BuiltinType::ShortAccum:
        case clang::BuiltinType::Accum:
        case clang::BuiltinType::LongAccum:
        case clang::BuiltinType::UShortAccum:
        case clang::BuiltinType::UAccum:
        case clang::BuiltinType::ULongAccum:
        case clang::BuiltinType::ShortFract:
        case clang::BuiltinType::Fract:
        case clang::BuiltinType::LongFract:
        case clang::BuiltinType::UShortFract:
        case clang::BuiltinType::UFract:
        case clang::BuiltinType::ULongFract:
        case clang::BuiltinType::SatShortAccum:
        case clang::BuiltinType::SatAccum:
        case clang::BuiltinType::SatLongAccum:
        case clang::BuiltinType::SatUShortAccum:
        case clang::BuiltinType::SatUAccum:
        case clang::BuiltinType::SatULongAccum:
        case clang::BuiltinType::SatShortFract:
        case clang::BuiltinType::SatFract:
        case clang::BuiltinType::SatLongFract:
        case clang::BuiltinType::SatUShortFract:
        case clang::BuiltinType::SatUFract:
        case clang::BuiltinType::SatULongFract:
        case clang::BuiltinType::Half:
        case clang::BuiltinType::Float:
        case clang::BuiltinType::Double:
        case clang::BuiltinType::LongDouble:
        case clang::BuiltinType::Float16:
        case clang::BuiltinType::BFloat16:
        case clang::BuiltinType::Float128:
        case clang::BuiltinType::NullPtr:
        case clang::BuiltinType::ObjCId:
        case clang::BuiltinType::ObjCClass:
        case clang::BuiltinType::ObjCSel:
        case clang::BuiltinType::OCLSampler:
        case clang::BuiltinType::OCLEvent:
        case clang::BuiltinType::OCLClkEvent:
        case clang::BuiltinType::OCLQueue:
        case clang::BuiltinType::OCLReserveID:
        case clang::BuiltinType::Dependent:
        case clang::BuiltinType::Overload:
        case clang::BuiltinType::BoundMember:
        case clang::BuiltinType::PseudoObject:
        case clang::BuiltinType::UnknownAny:
        case clang::BuiltinType::BuiltinFn:
        case clang::BuiltinType::ARCUnbridgedCast:
        case clang::BuiltinType::IncompleteMatrixIdx:
        case clang::BuiltinType::OMPArraySection:
        case clang::BuiltinType::OMPArrayShaping:
        case clang::BuiltinType::OMPIterator:
            break;
    }
}

static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage1dRO == clang::BuiltinType::OCLImage1dRO, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage1dArrayRO == clang::BuiltinType::OCLImage1dArrayRO, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage1dBufferRO == clang::BuiltinType::OCLImage1dBufferRO, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage2dRO == clang::BuiltinType::OCLImage2dRO, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage2dArrayRO == clang::BuiltinType::OCLImage2dArrayRO, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage2dDepthRO == clang::BuiltinType::OCLImage2dDepthRO, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage2dArrayDepthRO == clang::BuiltinType::OCLImage2dArrayDepthRO, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage2dMSAARO == clang::BuiltinType::OCLImage2dMSAARO, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage2dArrayMSAARO == clang::BuiltinType::OCLImage2dArrayMSAARO, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage2dMSAADepthRO == clang::BuiltinType::OCLImage2dMSAADepthRO, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage2dArrayMSAADepthRO == clang::BuiltinType::OCLImage2dArrayMSAADepthRO, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage3dRO == clang::BuiltinType::OCLImage3dRO, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage1dWO == clang::BuiltinType::OCLImage1dWO, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage1dArrayWO == clang::BuiltinType::OCLImage1dArrayWO, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage1dBufferWO == clang::BuiltinType::OCLImage1dBufferWO, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage2dWO == clang::BuiltinType::OCLImage2dWO, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage2dArrayWO == clang::BuiltinType::OCLImage2dArrayWO, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage2dDepthWO == clang::BuiltinType::OCLImage2dDepthWO, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage2dArrayDepthWO == clang::BuiltinType::OCLImage2dArrayDepthWO, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage2dMSAAWO == clang::BuiltinType::OCLImage2dMSAAWO, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage2dArrayMSAAWO == clang::BuiltinType::OCLImage2dArrayMSAAWO, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage2dMSAADepthWO == clang::BuiltinType::OCLImage2dMSAADepthWO, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage2dArrayMSAADepthWO == clang::BuiltinType::OCLImage2dArrayMSAADepthWO, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage3dWO == clang::BuiltinType::OCLImage3dWO, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage1dRW == clang::BuiltinType::OCLImage1dRW, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage1dArrayRW == clang::BuiltinType::OCLImage1dArrayRW, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage1dBufferRW == clang::BuiltinType::OCLImage1dBufferRW, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage2dRW == clang::BuiltinType::OCLImage2dRW, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage2dArrayRW == clang::BuiltinType::OCLImage2dArrayRW, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage2dDepthRW == clang::BuiltinType::OCLImage2dDepthRW, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage2dArrayDepthRW == clang::BuiltinType::OCLImage2dArrayDepthRW, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage2dMSAARW == clang::BuiltinType::OCLImage2dMSAARW, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage2dArrayMSAARW == clang::BuiltinType::OCLImage2dArrayMSAARW, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage2dMSAADepthRW == clang::BuiltinType::OCLImage2dMSAADepthRW, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage2dArrayMSAADepthRW == clang::BuiltinType::OCLImage2dArrayMSAADepthRW, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLImage3dRW == clang::BuiltinType::OCLImage3dRW, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLIntelSubgroupAVCMcePayload == clang::BuiltinType::OCLIntelSubgroupAVCMcePayload, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLIntelSubgroupAVCImePayload == clang::BuiltinType::OCLIntelSubgroupAVCImePayload, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLIntelSubgroupAVCRefPayload == clang::BuiltinType::OCLIntelSubgroupAVCRefPayload, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLIntelSubgroupAVCSicPayload == clang::BuiltinType::OCLIntelSubgroupAVCSicPayload, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLIntelSubgroupAVCMceResult == clang::BuiltinType::OCLIntelSubgroupAVCMceResult, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLIntelSubgroupAVCImeResult == clang::BuiltinType::OCLIntelSubgroupAVCImeResult, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLIntelSubgroupAVCRefResult == clang::BuiltinType::OCLIntelSubgroupAVCRefResult, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLIntelSubgroupAVCSicResult == clang::BuiltinType::OCLIntelSubgroupAVCSicResult, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLIntelSubgroupAVCImeResultSingleRefStreamout == clang::BuiltinType::OCLIntelSubgroupAVCImeResultSingleRefStreamout, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLIntelSubgroupAVCImeResultDualRefStreamout == clang::BuiltinType::OCLIntelSubgroupAVCImeResultDualRefStreamout, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLIntelSubgroupAVCImeSingleRefStreamin == clang::BuiltinType::OCLIntelSubgroupAVCImeSingleRefStreamin, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLIntelSubgroupAVCImeDualRefStreamin == clang::BuiltinType::OCLIntelSubgroupAVCImeDualRefStreamin, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveInt8 == clang::BuiltinType::SveInt8, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveInt16 == clang::BuiltinType::SveInt16, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveInt32 == clang::BuiltinType::SveInt32, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveInt64 == clang::BuiltinType::SveInt64, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveUint8 == clang::BuiltinType::SveUint8, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveUint16 == clang::BuiltinType::SveUint16, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveUint32 == clang::BuiltinType::SveUint32, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveUint64 == clang::BuiltinType::SveUint64, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveFloat16 == clang::BuiltinType::SveFloat16, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveFloat32 == clang::BuiltinType::SveFloat32, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveFloat64 == clang::BuiltinType::SveFloat64, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveBFloat16 == clang::BuiltinType::SveBFloat16, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveInt8x2 == clang::BuiltinType::SveInt8x2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveInt16x2 == clang::BuiltinType::SveInt16x2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveInt32x2 == clang::BuiltinType::SveInt32x2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveInt64x2 == clang::BuiltinType::SveInt64x2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveUint8x2 == clang::BuiltinType::SveUint8x2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveUint16x2 == clang::BuiltinType::SveUint16x2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveUint32x2 == clang::BuiltinType::SveUint32x2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveUint64x2 == clang::BuiltinType::SveUint64x2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveFloat16x2 == clang::BuiltinType::SveFloat16x2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveFloat32x2 == clang::BuiltinType::SveFloat32x2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveFloat64x2 == clang::BuiltinType::SveFloat64x2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveBFloat16x2 == clang::BuiltinType::SveBFloat16x2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveInt8x3 == clang::BuiltinType::SveInt8x3, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveInt16x3 == clang::BuiltinType::SveInt16x3, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveInt32x3 == clang::BuiltinType::SveInt32x3, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveInt64x3 == clang::BuiltinType::SveInt64x3, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveUint8x3 == clang::BuiltinType::SveUint8x3, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveUint16x3 == clang::BuiltinType::SveUint16x3, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveUint32x3 == clang::BuiltinType::SveUint32x3, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveUint64x3 == clang::BuiltinType::SveUint64x3, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveFloat16x3 == clang::BuiltinType::SveFloat16x3, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveFloat32x3 == clang::BuiltinType::SveFloat32x3, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveFloat64x3 == clang::BuiltinType::SveFloat64x3, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveBFloat16x3 == clang::BuiltinType::SveBFloat16x3, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveInt8x4 == clang::BuiltinType::SveInt8x4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveInt16x4 == clang::BuiltinType::SveInt16x4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveInt32x4 == clang::BuiltinType::SveInt32x4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveInt64x4 == clang::BuiltinType::SveInt64x4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveUint8x4 == clang::BuiltinType::SveUint8x4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveUint16x4 == clang::BuiltinType::SveUint16x4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveUint32x4 == clang::BuiltinType::SveUint32x4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveUint64x4 == clang::BuiltinType::SveUint64x4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveFloat16x4 == clang::BuiltinType::SveFloat16x4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveFloat32x4 == clang::BuiltinType::SveFloat32x4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveFloat64x4 == clang::BuiltinType::SveFloat64x4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveBFloat16x4 == clang::BuiltinType::SveBFloat16x4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSveBool == clang::BuiltinType::SveBool, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeVectorQuad == clang::BuiltinType::VectorQuad, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeVectorPair == clang::BuiltinType::VectorPair, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvInt8mf8 == clang::BuiltinType::RvvInt8mf8, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvInt8mf4 == clang::BuiltinType::RvvInt8mf4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvInt8mf2 == clang::BuiltinType::RvvInt8mf2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvInt8m1 == clang::BuiltinType::RvvInt8m1, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvInt8m2 == clang::BuiltinType::RvvInt8m2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvInt8m4 == clang::BuiltinType::RvvInt8m4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvInt8m8 == clang::BuiltinType::RvvInt8m8, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvUint8mf8 == clang::BuiltinType::RvvUint8mf8, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvUint8mf4 == clang::BuiltinType::RvvUint8mf4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvUint8mf2 == clang::BuiltinType::RvvUint8mf2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvUint8m1 == clang::BuiltinType::RvvUint8m1, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvUint8m2 == clang::BuiltinType::RvvUint8m2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvUint8m4 == clang::BuiltinType::RvvUint8m4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvUint8m8 == clang::BuiltinType::RvvUint8m8, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvInt16mf4 == clang::BuiltinType::RvvInt16mf4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvInt16mf2 == clang::BuiltinType::RvvInt16mf2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvInt16m1 == clang::BuiltinType::RvvInt16m1, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvInt16m2 == clang::BuiltinType::RvvInt16m2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvInt16m4 == clang::BuiltinType::RvvInt16m4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvInt16m8 == clang::BuiltinType::RvvInt16m8, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvUint16mf4 == clang::BuiltinType::RvvUint16mf4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvUint16mf2 == clang::BuiltinType::RvvUint16mf2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvUint16m1 == clang::BuiltinType::RvvUint16m1, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvUint16m2 == clang::BuiltinType::RvvUint16m2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvUint16m4 == clang::BuiltinType::RvvUint16m4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvUint16m8 == clang::BuiltinType::RvvUint16m8, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvInt32mf2 == clang::BuiltinType::RvvInt32mf2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvInt32m1 == clang::BuiltinType::RvvInt32m1, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvInt32m2 == clang::BuiltinType::RvvInt32m2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvInt32m4 == clang::BuiltinType::RvvInt32m4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvInt32m8 == clang::BuiltinType::RvvInt32m8, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvUint32mf2 == clang::BuiltinType::RvvUint32mf2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvUint32m1 == clang::BuiltinType::RvvUint32m1, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvUint32m2 == clang::BuiltinType::RvvUint32m2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvUint32m4 == clang::BuiltinType::RvvUint32m4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvUint32m8 == clang::BuiltinType::RvvUint32m8, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvInt64m1 == clang::BuiltinType::RvvInt64m1, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvInt64m2 == clang::BuiltinType::RvvInt64m2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvInt64m4 == clang::BuiltinType::RvvInt64m4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvInt64m8 == clang::BuiltinType::RvvInt64m8, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvUint64m1 == clang::BuiltinType::RvvUint64m1, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvUint64m2 == clang::BuiltinType::RvvUint64m2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvUint64m4 == clang::BuiltinType::RvvUint64m4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvUint64m8 == clang::BuiltinType::RvvUint64m8, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvFloat16mf4 == clang::BuiltinType::RvvFloat16mf4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvFloat16mf2 == clang::BuiltinType::RvvFloat16mf2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvFloat16m1 == clang::BuiltinType::RvvFloat16m1, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvFloat16m2 == clang::BuiltinType::RvvFloat16m2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvFloat16m4 == clang::BuiltinType::RvvFloat16m4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvFloat16m8 == clang::BuiltinType::RvvFloat16m8, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvFloat32mf2 == clang::BuiltinType::RvvFloat32mf2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvFloat32m1 == clang::BuiltinType::RvvFloat32m1, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvFloat32m2 == clang::BuiltinType::RvvFloat32m2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvFloat32m4 == clang::BuiltinType::RvvFloat32m4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvFloat32m8 == clang::BuiltinType::RvvFloat32m8, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvFloat64m1 == clang::BuiltinType::RvvFloat64m1, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvFloat64m2 == clang::BuiltinType::RvvFloat64m2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvFloat64m4 == clang::BuiltinType::RvvFloat64m4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvFloat64m8 == clang::BuiltinType::RvvFloat64m8, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvBool1 == clang::BuiltinType::RvvBool1, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvBool2 == clang::BuiltinType::RvvBool2, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvBool4 == clang::BuiltinType::RvvBool4, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvBool8 == clang::BuiltinType::RvvBool8, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvBool16 == clang::BuiltinType::RvvBool16, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvBool32 == clang::BuiltinType::RvvBool32, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeRvvBool64 == clang::BuiltinType::RvvBool64, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeVoid == clang::BuiltinType::Void, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeBool == clang::BuiltinType::Bool, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeChar_U == clang::BuiltinType::Char_U, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeUChar == clang::BuiltinType::UChar, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeWChar_U == clang::BuiltinType::WChar_U, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeChar8 == clang::BuiltinType::Char8, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeChar16 == clang::BuiltinType::Char16, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeChar32 == clang::BuiltinType::Char32, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeUShort == clang::BuiltinType::UShort, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeUInt == clang::BuiltinType::UInt, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeULong == clang::BuiltinType::ULong, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeULongLong == clang::BuiltinType::ULongLong, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeUInt128 == clang::BuiltinType::UInt128, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeChar_S == clang::BuiltinType::Char_S, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSChar == clang::BuiltinType::SChar, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeWChar_S == clang::BuiltinType::WChar_S, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeShort == clang::BuiltinType::Short, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeInt == clang::BuiltinType::Int, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeLong == clang::BuiltinType::Long, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeLongLong == clang::BuiltinType::LongLong, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeInt128 == clang::BuiltinType::Int128, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeShortAccum == clang::BuiltinType::ShortAccum, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeAccum == clang::BuiltinType::Accum, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeLongAccum == clang::BuiltinType::LongAccum, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeUShortAccum == clang::BuiltinType::UShortAccum, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeUAccum == clang::BuiltinType::UAccum, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeULongAccum == clang::BuiltinType::ULongAccum, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeShortFract == clang::BuiltinType::ShortFract, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeFract == clang::BuiltinType::Fract, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeLongFract == clang::BuiltinType::LongFract, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeUShortFract == clang::BuiltinType::UShortFract, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeUFract == clang::BuiltinType::UFract, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeULongFract == clang::BuiltinType::ULongFract, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSatShortAccum == clang::BuiltinType::SatShortAccum, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSatAccum == clang::BuiltinType::SatAccum, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSatLongAccum == clang::BuiltinType::SatLongAccum, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSatUShortAccum == clang::BuiltinType::SatUShortAccum, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSatUAccum == clang::BuiltinType::SatUAccum, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSatULongAccum == clang::BuiltinType::SatULongAccum, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSatShortFract == clang::BuiltinType::SatShortFract, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSatFract == clang::BuiltinType::SatFract, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSatLongFract == clang::BuiltinType::SatLongFract, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSatUShortFract == clang::BuiltinType::SatUShortFract, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSatUFract == clang::BuiltinType::SatUFract, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeSatULongFract == clang::BuiltinType::SatULongFract, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeHalf == clang::BuiltinType::Half, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeFloat == clang::BuiltinType::Float, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeDouble == clang::BuiltinType::Double, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeLongDouble == clang::BuiltinType::LongDouble, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeFloat16 == clang::BuiltinType::Float16, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeBFloat16 == clang::BuiltinType::BFloat16, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeFloat128 == clang::BuiltinType::Float128, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeNullPtr == clang::BuiltinType::NullPtr, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeObjCId == clang::BuiltinType::ObjCId, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeObjCClass == clang::BuiltinType::ObjCClass, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeObjCSel == clang::BuiltinType::ObjCSel, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLSampler == clang::BuiltinType::OCLSampler, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLEvent == clang::BuiltinType::OCLEvent, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLClkEvent == clang::BuiltinType::OCLClkEvent, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLQueue == clang::BuiltinType::OCLQueue, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOCLReserveID == clang::BuiltinType::OCLReserveID, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeDependent == clang::BuiltinType::Dependent, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOverload == clang::BuiltinType::Overload, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeBoundMember == clang::BuiltinType::BoundMember, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypePseudoObject == clang::BuiltinType::PseudoObject, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeUnknownAny == clang::BuiltinType::UnknownAny, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeBuiltinFn == clang::BuiltinType::BuiltinFn, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeARCUnbridgedCast == clang::BuiltinType::ARCUnbridgedCast, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeIncompleteMatrixIdx == clang::BuiltinType::IncompleteMatrixIdx, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOMPArraySection == clang::BuiltinType::OMPArraySection, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOMPArrayShaping == clang::BuiltinType::OMPArrayShaping, "");
static_assert((clang::BuiltinType::Kind)ZigClangBuiltinTypeOMPIterator == clang::BuiltinType::OMPIterator, "");

void ZigClang_detect_enum_CallingConv(clang::CallingConv x) {
    switch (x) {
        case clang::CC_C:
        case clang::CC_X86StdCall:
        case clang::CC_X86FastCall:
        case clang::CC_X86ThisCall:
        case clang::CC_X86VectorCall:
        case clang::CC_X86Pascal:
        case clang::CC_Win64:
        case clang::CC_X86_64SysV:
        case clang::CC_X86RegCall:
        case clang::CC_AAPCS:
        case clang::CC_AAPCS_VFP:
        case clang::CC_IntelOclBicc:
        case clang::CC_SpirFunction:
        case clang::CC_OpenCLKernel:
        case clang::CC_Swift:
        case clang::CC_SwiftAsync:
        case clang::CC_PreserveMost:
        case clang::CC_PreserveAll:
        case clang::CC_AArch64VectorCall:
            break;
    }
}

static_assert((clang::CallingConv)ZigClangCallingConv_C == clang::CC_C, "");
static_assert((clang::CallingConv)ZigClangCallingConv_X86StdCall == clang::CC_X86StdCall, "");
static_assert((clang::CallingConv)ZigClangCallingConv_X86FastCall == clang::CC_X86FastCall, "");
static_assert((clang::CallingConv)ZigClangCallingConv_X86ThisCall == clang::CC_X86ThisCall, "");
static_assert((clang::CallingConv)ZigClangCallingConv_X86VectorCall == clang::CC_X86VectorCall, "");
static_assert((clang::CallingConv)ZigClangCallingConv_X86Pascal == clang::CC_X86Pascal, "");
static_assert((clang::CallingConv)ZigClangCallingConv_Win64 == clang::CC_Win64, "");
static_assert((clang::CallingConv)ZigClangCallingConv_X86_64SysV == clang::CC_X86_64SysV, "");
static_assert((clang::CallingConv)ZigClangCallingConv_X86RegCall == clang::CC_X86RegCall, "");
static_assert((clang::CallingConv)ZigClangCallingConv_AAPCS == clang::CC_AAPCS, "");
static_assert((clang::CallingConv)ZigClangCallingConv_AAPCS_VFP == clang::CC_AAPCS_VFP, "");
static_assert((clang::CallingConv)ZigClangCallingConv_IntelOclBicc == clang::CC_IntelOclBicc, "");
static_assert((clang::CallingConv)ZigClangCallingConv_SpirFunction == clang::CC_SpirFunction, "");
static_assert((clang::CallingConv)ZigClangCallingConv_OpenCLKernel == clang::CC_OpenCLKernel, "");
static_assert((clang::CallingConv)ZigClangCallingConv_Swift == clang::CC_Swift, "");
static_assert((clang::CallingConv)ZigClangCallingConv_SwiftAsync == clang::CC_SwiftAsync, "");
static_assert((clang::CallingConv)ZigClangCallingConv_PreserveMost == clang::CC_PreserveMost, "");
static_assert((clang::CallingConv)ZigClangCallingConv_PreserveAll == clang::CC_PreserveAll, "");
static_assert((clang::CallingConv)ZigClangCallingConv_AArch64VectorCall == clang::CC_AArch64VectorCall, "");

void ZigClang_detect_enum_StorageClass(clang::StorageClass x) {
    switch (x) {
        case clang::SC_None:
        case clang::SC_Extern:
        case clang::SC_Static:
        case clang::SC_PrivateExtern:
        case clang::SC_Auto:
        case clang::SC_Register:
            break;
    }
}

static_assert((clang::StorageClass)ZigClangStorageClass_None == clang::SC_None, "");
static_assert((clang::StorageClass)ZigClangStorageClass_Extern == clang::SC_Extern, "");
static_assert((clang::StorageClass)ZigClangStorageClass_Static == clang::SC_Static, "");
static_assert((clang::StorageClass)ZigClangStorageClass_PrivateExtern == clang::SC_PrivateExtern, "");
static_assert((clang::StorageClass)ZigClangStorageClass_Auto == clang::SC_Auto, "");
static_assert((clang::StorageClass)ZigClangStorageClass_Register == clang::SC_Register, "");

void ZigClang_detect_enum_RoundingMode(llvm::RoundingMode x) {
    switch (x) {
        case llvm::RoundingMode::TowardZero:
        case llvm::RoundingMode::NearestTiesToEven:
        case llvm::RoundingMode::TowardPositive:
        case llvm::RoundingMode::TowardNegative:
        case llvm::RoundingMode::NearestTiesToAway:
        case llvm::RoundingMode::Dynamic:
        case llvm::RoundingMode::Invalid:
            break;
    }
}
static_assert((llvm::RoundingMode)ZigClangAPFloat_roundingMode_NearestTiesToEven == llvm::RoundingMode::NearestTiesToEven, "");
static_assert((llvm::RoundingMode)ZigClangAPFloat_roundingMode_TowardPositive == llvm::RoundingMode::TowardPositive, "");
static_assert((llvm::RoundingMode)ZigClangAPFloat_roundingMode_TowardNegative == llvm::RoundingMode::TowardNegative, "");
static_assert((llvm::RoundingMode)ZigClangAPFloat_roundingMode_TowardZero == llvm::RoundingMode::TowardZero, "");
static_assert((llvm::RoundingMode)ZigClangAPFloat_roundingMode_NearestTiesToAway == llvm::RoundingMode::NearestTiesToAway, "");
static_assert((llvm::RoundingMode)ZigClangAPFloat_roundingMode_Dynamic == llvm::RoundingMode::Dynamic, "");
static_assert((llvm::RoundingMode)ZigClangAPFloat_roundingMode_Invalid == llvm::RoundingMode::Invalid, "");

void ZigClang_detect_enum_StringKind(clang::StringLiteral::StringKind x) {
    switch (x) {
        case clang::StringLiteral::Ascii:
        case clang::StringLiteral::Wide:
        case clang::StringLiteral::UTF8:
        case clang::StringLiteral::UTF16:
        case clang::StringLiteral::UTF32:
            break;
    }
}
static_assert((clang::StringLiteral::StringKind)ZigClangStringLiteral_StringKind_Ascii == clang::StringLiteral::Ascii, "");
static_assert((clang::StringLiteral::StringKind)ZigClangStringLiteral_StringKind_Wide == clang::StringLiteral::Wide, "");
static_assert((clang::StringLiteral::StringKind)ZigClangStringLiteral_StringKind_UTF8 == clang::StringLiteral::UTF8, "");
static_assert((clang::StringLiteral::StringKind)ZigClangStringLiteral_StringKind_UTF16 == clang::StringLiteral::UTF16, "");
static_assert((clang::StringLiteral::StringKind)ZigClangStringLiteral_StringKind_UTF32 == clang::StringLiteral::UTF32, "");

void ZigClang_detect_enum_CharacterKind(clang::CharacterLiteral::CharacterKind x) {
    switch (x) {
        case clang::CharacterLiteral::Ascii:
        case clang::CharacterLiteral::Wide:
        case clang::CharacterLiteral::UTF8:
        case clang::CharacterLiteral::UTF16:
        case clang::CharacterLiteral::UTF32:
            break;
    }
}
static_assert((clang::CharacterLiteral::CharacterKind)ZigClangCharacterLiteral_CharacterKind_Ascii == clang::CharacterLiteral::Ascii, "");
static_assert((clang::CharacterLiteral::CharacterKind)ZigClangCharacterLiteral_CharacterKind_Wide == clang::CharacterLiteral::Wide, "");
static_assert((clang::CharacterLiteral::CharacterKind)ZigClangCharacterLiteral_CharacterKind_UTF8 == clang::CharacterLiteral::UTF8, "");
static_assert((clang::CharacterLiteral::CharacterKind)ZigClangCharacterLiteral_CharacterKind_UTF16 == clang::CharacterLiteral::UTF16, "");
static_assert((clang::CharacterLiteral::CharacterKind)ZigClangCharacterLiteral_CharacterKind_UTF32 == clang::CharacterLiteral::UTF32, "");

void ZigClang_detect_enum_ElaboratedTypeKeyword(clang::ElaboratedTypeKeyword x) {
    switch (x) {
        case clang::ETK_Struct:
        case clang::ETK_Interface:
        case clang::ETK_Union:
        case clang::ETK_Class:
        case clang::ETK_Enum:
        case clang::ETK_Typename:
        case clang::ETK_None:
            break;
    }
}
static_assert((clang::ElaboratedTypeKeyword)ZigClangETK_Struct == clang::ETK_Struct, "");
static_assert((clang::ElaboratedTypeKeyword)ZigClangETK_Interface == clang::ETK_Interface, "");
static_assert((clang::ElaboratedTypeKeyword)ZigClangETK_Union == clang::ETK_Union, "");
static_assert((clang::ElaboratedTypeKeyword)ZigClangETK_Class == clang::ETK_Class, "");
static_assert((clang::ElaboratedTypeKeyword)ZigClangETK_Enum == clang::ETK_Enum, "");
static_assert((clang::ElaboratedTypeKeyword)ZigClangETK_Typename == clang::ETK_Typename, "");
static_assert((clang::ElaboratedTypeKeyword)ZigClangETK_None == clang::ETK_None, "");

void ZigClang_detect_enum_EntityKind(clang::PreprocessedEntity::EntityKind x) {
    switch (x) {
        case clang::PreprocessedEntity::InvalidKind:
        case clang::PreprocessedEntity::MacroExpansionKind:
        case clang::PreprocessedEntity::MacroDefinitionKind:
        case clang::PreprocessedEntity::InclusionDirectiveKind:
            break;
    }
}
static_assert((clang::PreprocessedEntity::EntityKind)ZigClangPreprocessedEntity_InvalidKind == clang::PreprocessedEntity::InvalidKind, "");
static_assert((clang::PreprocessedEntity::EntityKind)ZigClangPreprocessedEntity_MacroExpansionKind == clang::PreprocessedEntity::MacroExpansionKind, "");
static_assert((clang::PreprocessedEntity::EntityKind)ZigClangPreprocessedEntity_MacroDefinitionKind == clang::PreprocessedEntity::MacroDefinitionKind, "");
static_assert((clang::PreprocessedEntity::EntityKind)ZigClangPreprocessedEntity_InclusionDirectiveKind == clang::PreprocessedEntity::InclusionDirectiveKind, "");


void ZigClang_detect_enum_ConstantExprKind(clang::Expr::ConstantExprKind x) {
    switch (x) {
        case clang::Expr::ConstantExprKind::Normal:
        case clang::Expr::ConstantExprKind::NonClassTemplateArgument:
        case clang::Expr::ConstantExprKind::ClassTemplateArgument:
        case clang::Expr::ConstantExprKind::ImmediateInvocation:
            break;
    }
}
static_assert((clang::Expr::ConstantExprKind)ZigClangExpr_ContantExprKind_Normal == clang::Expr::ConstantExprKind::Normal, "");
static_assert((clang::Expr::ConstantExprKind)ZigClangExpr_ContantExprKind_NonClassTemplateArgument == clang::Expr::ConstantExprKind::NonClassTemplateArgument, "");
static_assert((clang::Expr::ConstantExprKind)ZigClangExpr_ContantExprKind_ClassTemplateArgument == clang::Expr::ConstantExprKind::ClassTemplateArgument, "");
static_assert((clang::Expr::ConstantExprKind)ZigClangExpr_ContantExprKind_ImmediateInvocation == clang::Expr::ConstantExprKind::ImmediateInvocation, "");


static_assert(sizeof(ZigClangAPValue) == sizeof(clang::APValue), "");

static_assert(sizeof(ZigClangSourceLocation) == sizeof(clang::SourceLocation), "");
static ZigClangSourceLocation bitcast(clang::SourceLocation src) {
    ZigClangSourceLocation dest;
    memcpy(&dest, static_cast<void *>(&src), sizeof(ZigClangSourceLocation));
    return dest;
}
static clang::SourceLocation bitcast(ZigClangSourceLocation src) {
    clang::SourceLocation dest;
    memcpy(&dest, static_cast<void *>(&src), sizeof(ZigClangSourceLocation));
    return dest;
}

static_assert(sizeof(ZigClangQualType) == sizeof(clang::QualType), "");
static ZigClangQualType bitcast(clang::QualType src) {
    ZigClangQualType dest;
    memcpy(&dest, static_cast<void *>(&src), sizeof(ZigClangQualType));
    return dest;
}
static clang::QualType bitcast(ZigClangQualType src) {
    clang::QualType dest;
    memcpy(&dest, static_cast<void *>(&src), sizeof(ZigClangQualType));
    return dest;
}

static_assert(sizeof(ZigClangExprEvalResult) == sizeof(clang::Expr::EvalResult), "");
static ZigClangExprEvalResult bitcast(clang::Expr::EvalResult src) {
    ZigClangExprEvalResult dest;
    memcpy(&dest, static_cast<void *>(&src), sizeof(ZigClangExprEvalResult));
    return dest;
}

static_assert(sizeof(ZigClangAPValueLValueBase) == sizeof(clang::APValue::LValueBase), "");
static ZigClangAPValueLValueBase bitcast(clang::APValue::LValueBase src) {
    ZigClangAPValueLValueBase dest;
    memcpy(&dest, static_cast<void *>(&src), sizeof(ZigClangAPValueLValueBase));
    return dest;
}
static clang::APValue::LValueBase bitcast(ZigClangAPValueLValueBase src) {
    clang::APValue::LValueBase dest;
    memcpy(&dest, static_cast<void *>(&src), sizeof(ZigClangAPValueLValueBase));
    return dest;
}

static_assert(sizeof(ZigClangCompoundStmt_const_body_iterator) == sizeof(clang::CompoundStmt::const_body_iterator), "");
static ZigClangCompoundStmt_const_body_iterator bitcast(clang::CompoundStmt::const_body_iterator src) {
    ZigClangCompoundStmt_const_body_iterator dest;
    memcpy(&dest, static_cast<void *>(&src), sizeof(ZigClangCompoundStmt_const_body_iterator));
    return dest;
}

static_assert(sizeof(ZigClangDeclStmt_const_decl_iterator) == sizeof(clang::DeclStmt::const_decl_iterator), "");
static ZigClangDeclStmt_const_decl_iterator bitcast(clang::DeclStmt::const_decl_iterator src) {
    ZigClangDeclStmt_const_decl_iterator dest;
    memcpy(&dest, static_cast<void *>(&src), sizeof(ZigClangDeclStmt_const_decl_iterator));
    return dest;
}

static_assert(sizeof(ZigClangPreprocessingRecord_iterator) == sizeof(clang::PreprocessingRecord::iterator), "");
static ZigClangPreprocessingRecord_iterator bitcast(clang::PreprocessingRecord::iterator src) {
    ZigClangPreprocessingRecord_iterator dest;
    memcpy(&dest, static_cast<void *>(&src), sizeof(ZigClangPreprocessingRecord_iterator));
    return dest;
}
static clang::PreprocessingRecord::iterator bitcast(ZigClangPreprocessingRecord_iterator src) {
    clang::PreprocessingRecord::iterator dest;
    memcpy(&dest, static_cast<void *>(&src), sizeof(ZigClangPreprocessingRecord_iterator));
    return dest;
}

static_assert(sizeof(ZigClangRecordDecl_field_iterator) == sizeof(clang::RecordDecl::field_iterator), "");
static ZigClangRecordDecl_field_iterator bitcast(clang::RecordDecl::field_iterator src) {
    ZigClangRecordDecl_field_iterator dest;
    memcpy(&dest, static_cast<void *>(&src), sizeof(ZigClangRecordDecl_field_iterator));
    return dest;
}
static clang::RecordDecl::field_iterator bitcast(ZigClangRecordDecl_field_iterator src) {
    clang::RecordDecl::field_iterator dest;
    memcpy(&dest, static_cast<void *>(&src), sizeof(ZigClangRecordDecl_field_iterator));
    return dest;
}

static_assert(sizeof(ZigClangEnumDecl_enumerator_iterator) == sizeof(clang::EnumDecl::enumerator_iterator), "");
static ZigClangEnumDecl_enumerator_iterator bitcast(clang::EnumDecl::enumerator_iterator src) {
    ZigClangEnumDecl_enumerator_iterator dest;
    memcpy(&dest, static_cast<void *>(&src), sizeof(ZigClangEnumDecl_enumerator_iterator));
    return dest;
}
static clang::EnumDecl::enumerator_iterator bitcast(ZigClangEnumDecl_enumerator_iterator src) {
    clang::EnumDecl::enumerator_iterator dest;
    memcpy(&dest, static_cast<void *>(&src), sizeof(ZigClangEnumDecl_enumerator_iterator));
    return dest;
}


ZigClangSourceLocation ZigClangSourceManager_getSpellingLoc(const ZigClangSourceManager *self,
        ZigClangSourceLocation Loc)
{
    return bitcast(reinterpret_cast<const clang::SourceManager *>(self)->getSpellingLoc(bitcast(Loc)));
}

const char *ZigClangSourceManager_getFilename(const ZigClangSourceManager *self,
        ZigClangSourceLocation SpellingLoc)
{
    llvm::StringRef s = reinterpret_cast<const clang::SourceManager *>(self)->getFilename(bitcast(SpellingLoc));
    return (const char *)s.bytes_begin();
}

unsigned ZigClangSourceManager_getSpellingLineNumber(const ZigClangSourceManager *self,
        ZigClangSourceLocation Loc)
{
    return reinterpret_cast<const clang::SourceManager *>(self)->getSpellingLineNumber(bitcast(Loc));
}

unsigned ZigClangSourceManager_getSpellingColumnNumber(const ZigClangSourceManager *self,
        ZigClangSourceLocation Loc)
{
    return reinterpret_cast<const clang::SourceManager *>(self)->getSpellingColumnNumber(bitcast(Loc));
}

const char* ZigClangSourceManager_getCharacterData(const ZigClangSourceManager *self,
        ZigClangSourceLocation SL)
{
    return reinterpret_cast<const clang::SourceManager *>(self)->getCharacterData(bitcast(SL));
}

ZigClangQualType ZigClangASTContext_getPointerType(const ZigClangASTContext* self, ZigClangQualType T) {
    return bitcast(reinterpret_cast<const clang::ASTContext *>(self)->getPointerType(bitcast(T)));
}

unsigned ZigClangASTContext_getTypeAlign(const ZigClangASTContext* self, ZigClangQualType T) {
    return reinterpret_cast<const clang::ASTContext *>(self)->getTypeAlign(bitcast(T));
}

ZigClangASTContext *ZigClangASTUnit_getASTContext(ZigClangASTUnit *self) {
    clang::ASTContext *result = &reinterpret_cast<clang::ASTUnit *>(self)->getASTContext();
    return reinterpret_cast<ZigClangASTContext *>(result);
}

ZigClangSourceManager *ZigClangASTUnit_getSourceManager(ZigClangASTUnit *self) {
    clang::SourceManager *result = &reinterpret_cast<clang::ASTUnit *>(self)->getSourceManager();
    return reinterpret_cast<ZigClangSourceManager *>(result);
}

bool ZigClangASTUnit_visitLocalTopLevelDecls(ZigClangASTUnit *self, void *context,
    bool (*Fn)(void *context, const ZigClangDecl *decl))
{
    return reinterpret_cast<clang::ASTUnit *>(self)->visitLocalTopLevelDecls(context,
            reinterpret_cast<bool (*)(void *, const clang::Decl *)>(Fn));
}

struct ZigClangPreprocessingRecord_iterator ZigClangASTUnit_getLocalPreprocessingEntities_begin(
        struct ZigClangASTUnit *self)
{
    auto casted = reinterpret_cast<const clang::ASTUnit *>(self);
    return bitcast(casted->getLocalPreprocessingEntities().begin());
}

struct ZigClangPreprocessingRecord_iterator ZigClangASTUnit_getLocalPreprocessingEntities_end(
        struct ZigClangASTUnit *self)
{
    auto casted = reinterpret_cast<const clang::ASTUnit *>(self);
    return bitcast(casted->getLocalPreprocessingEntities().end());
}

struct ZigClangPreprocessedEntity *ZigClangPreprocessingRecord_iterator_deref(
        struct ZigClangPreprocessingRecord_iterator self)
{
    clang::PreprocessingRecord::iterator casted = bitcast(self);
    clang::PreprocessedEntity *result = *casted;
    return reinterpret_cast<ZigClangPreprocessedEntity *>(result);
}

const ZigClangRecordDecl *ZigClangRecordType_getDecl(const ZigClangRecordType *record_ty) {
    const clang::RecordDecl *record_decl = reinterpret_cast<const clang::RecordType *>(record_ty)->getDecl();
    return reinterpret_cast<const ZigClangRecordDecl *>(record_decl);
}

const ZigClangEnumDecl *ZigClangEnumType_getDecl(const ZigClangEnumType *enum_ty) {
    const clang::EnumDecl *enum_decl = reinterpret_cast<const clang::EnumType *>(enum_ty)->getDecl();
    return reinterpret_cast<const ZigClangEnumDecl *>(enum_decl);
}

const ZigClangTagDecl *ZigClangRecordDecl_getCanonicalDecl(const ZigClangRecordDecl *record_decl) {
    const clang::TagDecl *tag_decl = reinterpret_cast<const clang::RecordDecl*>(record_decl)->getCanonicalDecl();
    return reinterpret_cast<const ZigClangTagDecl *>(tag_decl);
}

const ZigClangFieldDecl *ZigClangFieldDecl_getCanonicalDecl(const ZigClangFieldDecl *field_decl) {
    const clang::FieldDecl *canon_decl = reinterpret_cast<const clang::FieldDecl*>(field_decl)->getCanonicalDecl();
    return reinterpret_cast<const ZigClangFieldDecl *>(canon_decl);
}

const ZigClangTagDecl *ZigClangEnumDecl_getCanonicalDecl(const ZigClangEnumDecl *enum_decl) {
    const clang::TagDecl *tag_decl = reinterpret_cast<const clang::EnumDecl*>(enum_decl)->getCanonicalDecl();
    return reinterpret_cast<const ZigClangTagDecl *>(tag_decl);
}

const ZigClangTypedefNameDecl *ZigClangTypedefNameDecl_getCanonicalDecl(const ZigClangTypedefNameDecl *self) {
    const clang::TypedefNameDecl *decl = reinterpret_cast<const clang::TypedefNameDecl*>(self)->getCanonicalDecl();
    return reinterpret_cast<const ZigClangTypedefNameDecl *>(decl);
}

const ZigClangFunctionDecl *ZigClangFunctionDecl_getCanonicalDecl(const ZigClangFunctionDecl *self) {
    const clang::FunctionDecl *decl = reinterpret_cast<const clang::FunctionDecl*>(self)->getCanonicalDecl();
    return reinterpret_cast<const ZigClangFunctionDecl *>(decl);
}

const ZigClangVarDecl *ZigClangVarDecl_getCanonicalDecl(const ZigClangVarDecl *self) {
    const clang::VarDecl *decl = reinterpret_cast<const clang::VarDecl*>(self)->getCanonicalDecl();
    return reinterpret_cast<const ZigClangVarDecl *>(decl);
}

const char* ZigClangVarDecl_getSectionAttribute(const struct ZigClangVarDecl *self, size_t *len) {
    auto casted = reinterpret_cast<const clang::VarDecl *>(self);
    if (const clang::SectionAttr *SA = casted->getAttr<clang::SectionAttr>()) {
        llvm::StringRef str_ref = SA->getName();
        *len = str_ref.size();
        return (const char *)str_ref.bytes_begin();
    }
    return nullptr;
}

bool ZigClangRecordDecl_getPackedAttribute(const ZigClangRecordDecl *zig_record_decl) {
    const clang::RecordDecl *record_decl = reinterpret_cast<const clang::RecordDecl *>(zig_record_decl);
    if (record_decl->getAttr<clang::PackedAttr>()) {
      return true;
    }
  return false;
}

unsigned ZigClangVarDecl_getAlignedAttribute(const struct ZigClangVarDecl *self, const ZigClangASTContext* ctx) {
    auto casted_self = reinterpret_cast<const clang::VarDecl *>(self);
    auto casted_ctx = const_cast<clang::ASTContext *>(reinterpret_cast<const clang::ASTContext *>(ctx));
    if (const clang::AlignedAttr *AA = casted_self->getAttr<clang::AlignedAttr>()) {
        return AA->getAlignment(*casted_ctx);
    }
    // Zero means no explicit alignment factor was specified
    return 0;
}

const struct ZigClangFunctionDecl *ZigClangVarDecl_getCleanupAttribute(const struct ZigClangVarDecl *self) {
    auto casted_self = reinterpret_cast<const clang::VarDecl *>(self);
    if (const clang::CleanupAttr *CA = casted_self->getAttr<clang::CleanupAttr>()) {
        return reinterpret_cast<const ZigClangFunctionDecl *>(CA->getFunctionDecl());
    }
    return nullptr;
}

unsigned ZigClangFieldDecl_getAlignedAttribute(const struct ZigClangFieldDecl *self, const ZigClangASTContext* ctx) {
    auto casted_self = reinterpret_cast<const clang::FieldDecl *>(self);
    auto casted_ctx = const_cast<clang::ASTContext *>(reinterpret_cast<const clang::ASTContext *>(ctx));
    if (const clang::AlignedAttr *AA = casted_self->getAttr<clang::AlignedAttr>()) {
        return AA->getAlignment(*casted_ctx);
    }
    // Zero means no explicit alignment factor was specified
    return 0;
}

unsigned ZigClangFunctionDecl_getAlignedAttribute(const struct ZigClangFunctionDecl *self, const ZigClangASTContext* ctx) {
    auto casted_self = reinterpret_cast<const clang::FunctionDecl *>(self);
    auto casted_ctx = const_cast<clang::ASTContext *>(reinterpret_cast<const clang::ASTContext *>(ctx));
    if (const clang::AlignedAttr *AA = casted_self->getAttr<clang::AlignedAttr>()) {
        return AA->getAlignment(*casted_ctx);
    }
    // Zero means no explicit alignment factor was specified
    return 0;
}

ZigClangQualType ZigClangParmVarDecl_getOriginalType(const struct ZigClangParmVarDecl *self) {
    return bitcast(reinterpret_cast<const clang::ParmVarDecl *>(self)->getOriginalType());
}

const ZigClangRecordDecl *ZigClangRecordDecl_getDefinition(const ZigClangRecordDecl *zig_record_decl) {
    const clang::RecordDecl *record_decl = reinterpret_cast<const clang::RecordDecl *>(zig_record_decl);
    const clang::RecordDecl *definition = record_decl->getDefinition();
    return reinterpret_cast<const ZigClangRecordDecl *>(definition);
}

const ZigClangEnumDecl *ZigClangEnumDecl_getDefinition(const ZigClangEnumDecl *zig_enum_decl) {
    const clang::EnumDecl *enum_decl = reinterpret_cast<const clang::EnumDecl *>(zig_enum_decl);
    const clang::EnumDecl *definition = enum_decl->getDefinition();
    return reinterpret_cast<const ZigClangEnumDecl *>(definition);
}

const ZigClangStringLiteral *ZigClangFileScopeAsmDecl_getAsmString(const ZigClangFileScopeAsmDecl *self) {
    const clang::StringLiteral *result = reinterpret_cast<const clang::FileScopeAsmDecl*>(self)->getAsmString();
    return reinterpret_cast<const ZigClangStringLiteral *>(result);
}

bool ZigClangRecordDecl_isUnion(const ZigClangRecordDecl *record_decl) {
    return reinterpret_cast<const clang::RecordDecl*>(record_decl)->isUnion();
}

bool ZigClangRecordDecl_isStruct(const ZigClangRecordDecl *record_decl) {
    return reinterpret_cast<const clang::RecordDecl*>(record_decl)->isStruct();
}

bool ZigClangRecordDecl_isAnonymousStructOrUnion(const ZigClangRecordDecl *record_decl) {
    return reinterpret_cast<const clang::RecordDecl*>(record_decl)->isAnonymousStructOrUnion();
}

const ZigClangNamedDecl* ZigClangDecl_castToNamedDecl(const ZigClangDecl *self) {
    auto casted = reinterpret_cast<const clang::Decl *>(self);
    auto cast = clang::dyn_cast<const clang::NamedDecl>(casted);
    return reinterpret_cast<const ZigClangNamedDecl *>(cast);
}

const char *ZigClangNamedDecl_getName_bytes_begin(const ZigClangNamedDecl *self) {
    auto casted = reinterpret_cast<const clang::NamedDecl *>(self);
    return (const char *)casted->getName().bytes_begin();
}

ZigClangDeclKind ZigClangDecl_getKind(const struct ZigClangDecl *self) {
    auto casted = reinterpret_cast<const clang::Decl *>(self);
    return (ZigClangDeclKind)casted->getKind();
}

const char *ZigClangDecl_getDeclKindName(const struct ZigClangDecl *self) {
    auto casted = reinterpret_cast<const clang::Decl *>(self);
    return casted->getDeclKindName();
}

ZigClangSourceLocation ZigClangRecordDecl_getLocation(const ZigClangRecordDecl *zig_record_decl) {
    const clang::RecordDecl *record_decl = reinterpret_cast<const clang::RecordDecl *>(zig_record_decl);
    return bitcast(record_decl->getLocation());
}

ZigClangSourceLocation ZigClangEnumDecl_getLocation(const ZigClangEnumDecl *self) {
    auto casted = reinterpret_cast<const clang::EnumDecl *>(self);
    return bitcast(casted->getLocation());
}

ZigClangSourceLocation ZigClangTypedefNameDecl_getLocation(const ZigClangTypedefNameDecl *self) {
    auto casted = reinterpret_cast<const clang::TypedefNameDecl *>(self);
    return bitcast(casted->getLocation());
}

ZigClangSourceLocation ZigClangDecl_getLocation(const ZigClangDecl *self) {
    auto casted = reinterpret_cast<const clang::Decl *>(self);
    return bitcast(casted->getLocation());
}

bool ZigClangSourceLocation_eq(ZigClangSourceLocation zig_a, ZigClangSourceLocation zig_b) {
    clang::SourceLocation a = bitcast(zig_a);
    clang::SourceLocation b = bitcast(zig_b);
    return a == b;
}

ZigClangQualType ZigClangEnumDecl_getIntegerType(const ZigClangEnumDecl *self) {
    return bitcast(reinterpret_cast<const clang::EnumDecl *>(self)->getIntegerType());
}

struct ZigClangQualType ZigClangFunctionDecl_getType(const struct ZigClangFunctionDecl *self) {
    auto casted = reinterpret_cast<const clang::FunctionDecl *>(self);
    return bitcast(casted->getType());
}

struct ZigClangSourceLocation ZigClangFunctionDecl_getLocation(const struct ZigClangFunctionDecl *self) {
    auto casted = reinterpret_cast<const clang::FunctionDecl *>(self);
    return bitcast(casted->getLocation());
}

bool ZigClangFunctionDecl_hasBody(const struct ZigClangFunctionDecl *self) {
    auto casted = reinterpret_cast<const clang::FunctionDecl *>(self);
    return casted->hasBody();
}

enum ZigClangStorageClass ZigClangFunctionDecl_getStorageClass(const struct ZigClangFunctionDecl *self) {
    auto casted = reinterpret_cast<const clang::FunctionDecl *>(self);
    return (ZigClangStorageClass)casted->getStorageClass();
}

const struct ZigClangParmVarDecl *ZigClangFunctionDecl_getParamDecl(const struct ZigClangFunctionDecl *self,
        unsigned i)
{
    auto casted = reinterpret_cast<const clang::FunctionDecl *>(self);
    const clang::ParmVarDecl *parm_var_decl = casted->getParamDecl(i);
    return reinterpret_cast<const ZigClangParmVarDecl *>(parm_var_decl);
}

const struct ZigClangStmt *ZigClangFunctionDecl_getBody(const struct ZigClangFunctionDecl *self) {
    auto casted = reinterpret_cast<const clang::FunctionDecl *>(self);
    const clang::Stmt *stmt = casted->getBody();
    return reinterpret_cast<const ZigClangStmt *>(stmt);
}

bool ZigClangFunctionDecl_doesDeclarationForceExternallyVisibleDefinition(const struct ZigClangFunctionDecl *self) {
    auto casted = reinterpret_cast<const clang::FunctionDecl *>(self);
    return casted->doesDeclarationForceExternallyVisibleDefinition();
}

bool ZigClangFunctionDecl_isThisDeclarationADefinition(const struct ZigClangFunctionDecl *self) {
    auto casted = reinterpret_cast<const clang::FunctionDecl *>(self);
    return casted->isThisDeclarationADefinition();
}

bool ZigClangFunctionDecl_doesThisDeclarationHaveABody(const struct ZigClangFunctionDecl *self) {
    auto casted = reinterpret_cast<const clang::FunctionDecl *>(self);
    return casted->doesThisDeclarationHaveABody();
}

bool ZigClangFunctionDecl_isDefined(const struct ZigClangFunctionDecl *self) {
    auto casted = reinterpret_cast<const clang::FunctionDecl *>(self);
    return casted->isDefined();
}

const ZigClangFunctionDecl* ZigClangFunctionDecl_getDefinition(const struct ZigClangFunctionDecl *self) {
    auto casted = reinterpret_cast<const clang::FunctionDecl *>(self);
    return reinterpret_cast<const ZigClangFunctionDecl *>(casted->getDefinition());
}

bool ZigClangTagDecl_isThisDeclarationADefinition(const struct ZigClangTagDecl *self) {
    auto casted = reinterpret_cast<const clang::TagDecl *>(self);
    return casted->isThisDeclarationADefinition();
}

bool ZigClangFunctionDecl_isInlineSpecified(const struct ZigClangFunctionDecl *self) {
    auto casted = reinterpret_cast<const clang::FunctionDecl *>(self);
    return casted->isInlineSpecified();
}

const char* ZigClangFunctionDecl_getSectionAttribute(const struct ZigClangFunctionDecl *self, size_t *len) {
    auto casted = reinterpret_cast<const clang::FunctionDecl *>(self);
    if (const clang::SectionAttr *SA = casted->getAttr<clang::SectionAttr>()) {
        llvm::StringRef str_ref = SA->getName();
        *len = str_ref.size();
        return (const char *)str_ref.bytes_begin();
    }
    return nullptr;
}

const ZigClangExpr *ZigClangOpaqueValueExpr_getSourceExpr(const ZigClangOpaqueValueExpr *self) {
    auto casted = reinterpret_cast<const clang::OpaqueValueExpr *>(self);
    return reinterpret_cast<const ZigClangExpr *>(casted->getSourceExpr());
}

const ZigClangTypedefNameDecl *ZigClangTypedefType_getDecl(const ZigClangTypedefType *self) {
    auto casted = reinterpret_cast<const clang::TypedefType *>(self);
    const clang::TypedefNameDecl *name_decl = casted->getDecl();
    return reinterpret_cast<const ZigClangTypedefNameDecl *>(name_decl);
}

ZigClangQualType ZigClangTypedefNameDecl_getUnderlyingType(const ZigClangTypedefNameDecl *self) {
    auto casted = reinterpret_cast<const clang::TypedefNameDecl *>(self);
    clang::QualType ty = casted->getUnderlyingType();
    return bitcast(ty);
}

ZigClangQualType ZigClangQualType_getCanonicalType(ZigClangQualType self) {
    clang::QualType qt = bitcast(self);
    return bitcast(qt.getCanonicalType());
}

const ZigClangType *ZigClangQualType_getTypePtr(ZigClangQualType self) {
    clang::QualType qt = bitcast(self);
    const clang::Type *ty = qt.getTypePtr();
    return reinterpret_cast<const ZigClangType *>(ty);
}

ZigClangTypeClass ZigClangQualType_getTypeClass(ZigClangQualType self) {
    clang::QualType ty = bitcast(self);
    return (ZigClangTypeClass)(ty->getTypeClass());
}

void ZigClangQualType_addConst(ZigClangQualType *self) {
    reinterpret_cast<clang::QualType *>(self)->addConst();
}

bool ZigClangQualType_eq(ZigClangQualType zig_t1, ZigClangQualType zig_t2) {
    clang::QualType t1 = bitcast(zig_t1);
    clang::QualType t2 = bitcast(zig_t2);
    if (t1.isConstQualified() != t2.isConstQualified()) {
        return false;
    }
    if (t1.isVolatileQualified() != t2.isVolatileQualified()) {
        return false;
    }
    if (t1.isRestrictQualified() != t2.isRestrictQualified()) {
        return false;
    }
    return t1.getTypePtr() == t2.getTypePtr();
}

bool ZigClangQualType_isConstQualified(ZigClangQualType self) {
    clang::QualType qt = bitcast(self);
    return qt.isConstQualified();
}

bool ZigClangQualType_isVolatileQualified(ZigClangQualType self) {
    clang::QualType qt = bitcast(self);
    return qt.isVolatileQualified();
}

bool ZigClangQualType_isRestrictQualified(ZigClangQualType self) {
    clang::QualType qt = bitcast(self);
    return qt.isRestrictQualified();
}

ZigClangTypeClass ZigClangType_getTypeClass(const ZigClangType *self) {
    auto casted = reinterpret_cast<const clang::Type *>(self);
    clang::Type::TypeClass tc = casted->getTypeClass();
    return (ZigClangTypeClass)tc;
}

ZigClangQualType ZigClangType_getPointeeType(const ZigClangType *self) {
    auto casted = reinterpret_cast<const clang::Type *>(self);
    return bitcast(casted->getPointeeType());
}

bool ZigClangType_isBooleanType(const ZigClangType *self) {
    auto casted = reinterpret_cast<const clang::Type *>(self);
    return casted->isBooleanType();
}

bool ZigClangType_isVoidType(const ZigClangType *self) {
    auto casted = reinterpret_cast<const clang::Type *>(self);
    return casted->isVoidType();
}

bool ZigClangType_isArrayType(const ZigClangType *self) {
    auto casted = reinterpret_cast<const clang::Type *>(self);
    return casted->isArrayType();
}

bool ZigClangType_isRecordType(const ZigClangType *self) {
    auto casted = reinterpret_cast<const clang::Type *>(self);
    return casted->isRecordType();
}

bool ZigClangType_isVectorType(const ZigClangType *self) {
    auto casted = reinterpret_cast<const clang::Type *>(self);
    return casted->isVectorType();
}

bool ZigClangType_isIncompleteOrZeroLengthArrayType(const ZigClangQualType *self,
        const struct ZigClangASTContext *ctx)
{
    auto casted_ctx = reinterpret_cast<const clang::ASTContext *>(ctx);
    auto casted = reinterpret_cast<const clang::QualType *>(self);
    auto casted_type = reinterpret_cast<const clang::Type *>(self);
    if (casted_type->isIncompleteArrayType())
        return true;

    clang::QualType elem_type = *casted;
    while (const clang::ConstantArrayType *ArrayT = casted_ctx->getAsConstantArrayType(elem_type)) {
        if (ArrayT->getSize() == 0)
            return true;

        elem_type = ArrayT->getElementType();
    }

    return false;
}

bool ZigClangType_isConstantArrayType(const ZigClangType *self) {
    auto casted = reinterpret_cast<const clang::Type *>(self);
    return casted->isConstantArrayType();
}

const char *ZigClangType_getTypeClassName(const ZigClangType *self) {
    auto casted = reinterpret_cast<const clang::Type *>(self);
    return casted->getTypeClassName();
}

const ZigClangArrayType *ZigClangType_getAsArrayTypeUnsafe(const ZigClangType *self) {
    auto casted = reinterpret_cast<const clang::Type *>(self);
    const clang::ArrayType *result = casted->getAsArrayTypeUnsafe();
    return reinterpret_cast<const ZigClangArrayType *>(result);
}

const ZigClangRecordType *ZigClangType_getAsRecordType(const ZigClangType *self) {
    auto casted = reinterpret_cast<const clang::Type *>(self);
    const clang::RecordType *result = casted->getAsStructureType();
    return reinterpret_cast<const ZigClangRecordType *>(result);
}

const ZigClangRecordType *ZigClangType_getAsUnionType(const ZigClangType *self) {
    auto casted = reinterpret_cast<const clang::Type *>(self);
    const clang::RecordType *result = casted->getAsUnionType();
    return reinterpret_cast<const ZigClangRecordType *>(result);
}

ZigClangSourceLocation ZigClangStmt_getBeginLoc(const ZigClangStmt *self) {
    auto casted = reinterpret_cast<const clang::Stmt *>(self);
    return bitcast(casted->getBeginLoc());
}

bool ZigClangStmt_classof_Expr(const ZigClangStmt *self) {
    auto casted = reinterpret_cast<const clang::Stmt *>(self);
    return clang::Expr::classof(casted);
}

ZigClangStmtClass ZigClangStmt_getStmtClass(const ZigClangStmt *self) {
    auto casted = reinterpret_cast<const clang::Stmt *>(self);
    return (ZigClangStmtClass)casted->getStmtClass();
}

ZigClangStmtClass ZigClangExpr_getStmtClass(const ZigClangExpr *self) {
    auto casted = reinterpret_cast<const clang::Expr *>(self);
    return (ZigClangStmtClass)casted->getStmtClass();
}

ZigClangQualType ZigClangExpr_getType(const ZigClangExpr *self) {
    auto casted = reinterpret_cast<const clang::Expr *>(self);
    return bitcast(casted->getType());
}

ZigClangSourceLocation ZigClangExpr_getBeginLoc(const ZigClangExpr *self) {
    auto casted = reinterpret_cast<const clang::Expr *>(self);
    return bitcast(casted->getBeginLoc());
}

bool ZigClangExpr_EvaluateAsBooleanCondition(const ZigClangExpr *self, bool *result,
        const struct ZigClangASTContext *ctx, bool in_constant_context)
{
    auto casted = reinterpret_cast<const clang::Expr *>(self);
    auto casted_ctx = reinterpret_cast<const clang::ASTContext *>(ctx);
    return casted->EvaluateAsBooleanCondition(*result, *casted_ctx, in_constant_context);
}

bool ZigClangExpr_EvaluateAsFloat(const ZigClangExpr *self, ZigClangAPFloat **result,
        const struct ZigClangASTContext *ctx)
{
    llvm::APFloat *ap_float = new llvm::APFloat(0.0f);
    *result = reinterpret_cast<ZigClangAPFloat *>(ap_float);
    auto casted = reinterpret_cast<const clang::Expr *>(self);
    auto casted_ctx = reinterpret_cast<const clang::ASTContext *>(ctx);
    return casted->EvaluateAsFloat(*ap_float, *casted_ctx);
}

bool ZigClangExpr_EvaluateAsConstantExpr(const ZigClangExpr *self, ZigClangExprEvalResult *result,
        ZigClangExpr_ConstantExprKind kind, const struct ZigClangASTContext *ctx)
{
    auto casted_self = reinterpret_cast<const clang::Expr *>(self);
    auto casted_ctx = reinterpret_cast<const clang::ASTContext *>(ctx);
    clang::Expr::EvalResult eval_result;
    if (!casted_self->EvaluateAsConstantExpr(eval_result, *casted_ctx, (clang::Expr::ConstantExprKind)kind)) {
        return false;
    }
    *result = bitcast(eval_result);
    return true;
}

const ZigClangExpr *ZigClangInitListExpr_getInit(const ZigClangInitListExpr *self, unsigned i) {
    auto casted = reinterpret_cast<const clang::InitListExpr *>(self);
    const clang::Expr *result = casted->getInit(i);
    return reinterpret_cast<const ZigClangExpr *>(result);
}

const ZigClangExpr *ZigClangInitListExpr_getArrayFiller(const ZigClangInitListExpr *self) {
    auto casted = reinterpret_cast<const clang::InitListExpr *>(self);
    const clang::Expr *result = casted->getArrayFiller();
    return reinterpret_cast<const ZigClangExpr *>(result);
}

const ZigClangFieldDecl *ZigClangInitListExpr_getInitializedFieldInUnion(const ZigClangInitListExpr *self) {
    auto casted = reinterpret_cast<const clang::InitListExpr *>(self);
    const clang::FieldDecl *result = casted->getInitializedFieldInUnion();
    return reinterpret_cast<const ZigClangFieldDecl *>(result);
}

unsigned ZigClangInitListExpr_getNumInits(const ZigClangInitListExpr *self) {
    auto casted = reinterpret_cast<const clang::InitListExpr *>(self);
    return casted->getNumInits();
}

ZigClangAPValueKind ZigClangAPValue_getKind(const ZigClangAPValue *self) {
    auto casted = reinterpret_cast<const clang::APValue *>(self);
    return (ZigClangAPValueKind)casted->getKind();
}

const ZigClangAPSInt *ZigClangAPValue_getInt(const ZigClangAPValue *self) {
    auto casted = reinterpret_cast<const clang::APValue *>(self);
    const llvm::APSInt *result = &casted->getInt();
    return reinterpret_cast<const ZigClangAPSInt *>(result);
}

unsigned ZigClangAPValue_getArrayInitializedElts(const ZigClangAPValue *self) {
    auto casted = reinterpret_cast<const clang::APValue *>(self);
    return casted->getArrayInitializedElts();
}

const ZigClangAPValue *ZigClangAPValue_getArrayInitializedElt(const ZigClangAPValue *self, unsigned i) {
    auto casted = reinterpret_cast<const clang::APValue *>(self);
    const clang::APValue *result = &casted->getArrayInitializedElt(i);
    return reinterpret_cast<const ZigClangAPValue *>(result);
}

const ZigClangAPValue *ZigClangAPValue_getArrayFiller(const ZigClangAPValue *self) {
    auto casted = reinterpret_cast<const clang::APValue *>(self);
    const clang::APValue *result = &casted->getArrayFiller();
    return reinterpret_cast<const ZigClangAPValue *>(result);
}

unsigned ZigClangAPValue_getArraySize(const ZigClangAPValue *self) {
    auto casted = reinterpret_cast<const clang::APValue *>(self);
    return casted->getArraySize();
}

const ZigClangAPSInt *ZigClangAPSInt_negate(const ZigClangAPSInt *self) {
    auto casted = reinterpret_cast<const llvm::APSInt *>(self);
    llvm::APSInt *result = new llvm::APSInt();
    *result = *casted;
    *result = -*result;
    return reinterpret_cast<const ZigClangAPSInt *>(result);
}

void ZigClangAPSInt_free(const ZigClangAPSInt *self) {
    auto casted = reinterpret_cast<const llvm::APSInt *>(self);
    delete casted;
}

bool ZigClangAPSInt_isSigned(const ZigClangAPSInt *self) {
    auto casted = reinterpret_cast<const llvm::APSInt *>(self);
    return casted->isSigned();
}

bool ZigClangAPSInt_isNegative(const ZigClangAPSInt *self) {
    auto casted = reinterpret_cast<const llvm::APSInt *>(self);
    return casted->isNegative();
}

const uint64_t *ZigClangAPSInt_getRawData(const ZigClangAPSInt *self) {
    auto casted = reinterpret_cast<const llvm::APSInt *>(self);
    return casted->getRawData();
}

unsigned ZigClangAPSInt_getNumWords(const ZigClangAPSInt *self) {
    auto casted = reinterpret_cast<const llvm::APSInt *>(self);
    return casted->getNumWords();
}

bool ZigClangAPSInt_lessThanEqual(const ZigClangAPSInt *self, uint64_t rhs) {
    auto casted = reinterpret_cast<const llvm::APSInt *>(self);
    return casted->ule(rhs);
}

uint64_t ZigClangAPInt_getLimitedValue(const ZigClangAPInt *self, uint64_t limit) {
    auto casted = reinterpret_cast<const llvm::APInt *>(self);
    return casted->getLimitedValue(limit);
}

const ZigClangExpr *ZigClangAPValueLValueBase_dyn_cast_Expr(ZigClangAPValueLValueBase self) {
    clang::APValue::LValueBase casted = bitcast(self);
    const clang::Expr *expr = casted.dyn_cast<const clang::Expr *>();
    return reinterpret_cast<const ZigClangExpr *>(expr);
}

ZigClangAPValueLValueBase ZigClangAPValue_getLValueBase(const ZigClangAPValue *self) {
    auto casted = reinterpret_cast<const clang::APValue *>(self);
    clang::APValue::LValueBase lval_base = casted->getLValueBase();
    return bitcast(lval_base);
}

ZigClangASTUnit *ZigClangLoadFromCommandLine(const char **args_begin, const char **args_end,
    struct Stage2ErrorMsg **errors_ptr, size_t *errors_len, const char *resources_path)
{
    clang::IntrusiveRefCntPtr<clang::DiagnosticsEngine> diags(clang::CompilerInstance::createDiagnostics(new clang::DiagnosticOptions));

    std::shared_ptr<clang::PCHContainerOperations> pch_container_ops = std::make_shared<clang::PCHContainerOperations>();

    bool only_local_decls = true;
    bool user_files_are_volatile = true;
    bool allow_pch_with_compiler_errors = false;
    bool single_file_parse = false;
    bool for_serialization = false;
    bool retain_excluded_conditional_blocks = false;
    std::unique_ptr<clang::ASTUnit> err_unit;
    clang::ASTUnit *ast_unit = clang::ASTUnit::LoadFromCommandLine(
            args_begin, args_end,
            pch_container_ops, diags, resources_path,
            only_local_decls, clang::CaptureDiagsKind::All, clang::None, true, 0, clang::TU_Complete,
            false, false, allow_pch_with_compiler_errors, clang::SkipFunctionBodiesScope::None,
            single_file_parse, user_files_are_volatile, for_serialization, retain_excluded_conditional_blocks,
            clang::None, &err_unit, nullptr);

    *errors_len = 0;

    // Early failures in LoadFromCommandLine may return with ErrUnit unset.
    if (!ast_unit && !err_unit) {
        return nullptr;
    }

    if (diags->hasErrorOccurred()) {
        // Take ownership of the err_unit ASTUnit object so that it won't be
        // free'd when we return, invalidating the error message pointers
        clang::ASTUnit *unit = ast_unit ? ast_unit : err_unit.release();
        Stage2ErrorMsg *errors = nullptr;

        for (clang::ASTUnit::stored_diag_iterator it = unit->stored_diag_begin(),
             it_end = unit->stored_diag_end(); it != it_end; ++it)
        {
            switch (it->getLevel()) {
                case clang::DiagnosticsEngine::Ignored:
                case clang::DiagnosticsEngine::Note:
                case clang::DiagnosticsEngine::Remark:
                case clang::DiagnosticsEngine::Warning:
                    continue;
                case clang::DiagnosticsEngine::Error:
                case clang::DiagnosticsEngine::Fatal:
                    break;
            }

            llvm::StringRef msg_str_ref = it->getMessage();

            *errors_len += 1;
            errors = reinterpret_cast<Stage2ErrorMsg*>(realloc(errors, sizeof(Stage2ErrorMsg) * *errors_len));
            if (errors == nullptr) abort();
            Stage2ErrorMsg *msg = &errors[*errors_len - 1];
            memset(msg, 0, sizeof(*msg));

            msg->msg_ptr = (const char *)msg_str_ref.bytes_begin();
            msg->msg_len = msg_str_ref.size();

            clang::FullSourceLoc fsl = it->getLocation();
            // Expand the location if possible
            fsl = fsl.getFileLoc();

            // The only known way to obtain a Loc without a manager associated
            // to it is if you have a lot of errors clang emits "too many errors
            // emitted, stopping now"
            if (fsl.hasManager()) {
                const clang::SourceManager &SM = fsl.getManager();

                clang::PresumedLoc presumed_loc = SM.getPresumedLoc(fsl);
                assert(!presumed_loc.isInvalid());

                msg->line = presumed_loc.getLine() - 1;
                msg->column = presumed_loc.getColumn() - 1;

                clang::StringRef filename = presumed_loc.getFilename();
                if (!filename.empty()) {
                    msg->filename_ptr = (const char *)filename.bytes_begin();
                    msg->filename_len = filename.size();
                }

                bool invalid;
                clang::StringRef buffer = fsl.getBufferData(&invalid);

                if (!invalid) {
                    msg->source = (const char *)buffer.bytes_begin();
                    msg->offset = SM.getFileOffset(fsl);
                }
            }
        }

        *errors_ptr = errors;

        return nullptr;
    }

    return reinterpret_cast<ZigClangASTUnit *>(ast_unit);
}

void ZigClangErrorMsg_delete(Stage2ErrorMsg *ptr, size_t len) {
    free(ptr);
}

void ZigClangASTUnit_delete(struct ZigClangASTUnit *self) {
    delete reinterpret_cast<clang::ASTUnit *>(self);
}

struct ZigClangQualType ZigClangVarDecl_getType(const struct ZigClangVarDecl *self) {
    auto casted = reinterpret_cast<const clang::VarDecl *>(self);
    return bitcast(casted->getType());
}

struct ZigClangQualType ZigClangVarDecl_getTypeSourceInfo_getType(const struct ZigClangVarDecl *self) {
    auto casted = reinterpret_cast<const clang::VarDecl *>(self);
    return bitcast(casted->getTypeSourceInfo()->getType());
}

const struct ZigClangExpr *ZigClangVarDecl_getInit(const struct ZigClangVarDecl *self) {
    auto casted = reinterpret_cast<const clang::VarDecl *>(self);
    return reinterpret_cast<const ZigClangExpr *>(casted->getInit());
}

enum ZigClangVarDecl_TLSKind ZigClangVarDecl_getTLSKind(const ZigClangVarDecl *self) {
    auto casted = reinterpret_cast<const clang::VarDecl *>(self);
    return (ZigClangVarDecl_TLSKind)casted->getTLSKind();
}

struct ZigClangSourceLocation ZigClangVarDecl_getLocation(const struct ZigClangVarDecl *self) {
    auto casted = reinterpret_cast<const clang::VarDecl *>(self);
    return bitcast(casted->getLocation());
}

bool ZigClangVarDecl_hasExternalStorage(const struct ZigClangVarDecl *self) {
    auto casted = reinterpret_cast<const clang::VarDecl *>(self);
    return casted->hasExternalStorage();
}

bool ZigClangVarDecl_isFileVarDecl(const struct ZigClangVarDecl *self) {
    auto casted = reinterpret_cast<const clang::VarDecl *>(self);
    return casted->isFileVarDecl();
}

bool ZigClangVarDecl_hasInit(const struct ZigClangVarDecl *self) {
    auto casted = reinterpret_cast<const clang::VarDecl *>(self);
    return casted->hasInit();
}

const ZigClangAPValue * ZigClangVarDecl_evaluateValue(const struct ZigClangVarDecl *self) {
    auto casted = reinterpret_cast<const clang::VarDecl *>(self);
    const clang::APValue *result = casted->evaluateValue();
    return reinterpret_cast<const ZigClangAPValue *>(result);
}

enum ZigClangStorageClass ZigClangVarDecl_getStorageClass(const struct ZigClangVarDecl *self) {
    auto casted = reinterpret_cast<const clang::VarDecl *>(self);
    return (ZigClangStorageClass)casted->getStorageClass();
}

bool ZigClangVarDecl_isStaticLocal(const struct ZigClangVarDecl *self) {
    auto casted = reinterpret_cast<const clang::VarDecl *>(self);
    return casted->isStaticLocal();
}

enum ZigClangBuiltinTypeKind ZigClangBuiltinType_getKind(const struct ZigClangBuiltinType *self) {
    auto casted = reinterpret_cast<const clang::BuiltinType *>(self);
    return (ZigClangBuiltinTypeKind)casted->getKind();
}

bool ZigClangFunctionType_getNoReturnAttr(const struct ZigClangFunctionType *self) {
    auto casted = reinterpret_cast<const clang::FunctionType *>(self);
    return casted->getNoReturnAttr();
}

enum ZigClangCallingConv ZigClangFunctionType_getCallConv(const struct ZigClangFunctionType *self) {
    auto casted = reinterpret_cast<const clang::FunctionType *>(self);
    return (ZigClangCallingConv)casted->getCallConv();
}

struct ZigClangQualType ZigClangFunctionType_getReturnType(const struct ZigClangFunctionType *self) {
    auto casted = reinterpret_cast<const clang::FunctionType *>(self);
    return bitcast(casted->getReturnType());
}

const struct ZigClangExpr *ZigClangGenericSelectionExpr_getResultExpr(const struct ZigClangGenericSelectionExpr *self) {
    auto casted = reinterpret_cast<const clang::GenericSelectionExpr *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getResultExpr());
}

bool ZigClangFunctionProtoType_isVariadic(const struct ZigClangFunctionProtoType *self) {
    auto casted = reinterpret_cast<const clang::FunctionProtoType *>(self);
    return casted->isVariadic();
}

unsigned ZigClangFunctionProtoType_getNumParams(const struct ZigClangFunctionProtoType *self) {
    auto casted = reinterpret_cast<const clang::FunctionProtoType *>(self);
    return casted->getNumParams();
}

struct ZigClangQualType ZigClangFunctionProtoType_getParamType(const struct ZigClangFunctionProtoType *self,
        unsigned index)
{
    auto casted = reinterpret_cast<const clang::FunctionProtoType *>(self);
    return bitcast(casted->getParamType(index));
}

struct ZigClangQualType ZigClangFunctionProtoType_getReturnType(const struct ZigClangFunctionProtoType *self) {
    auto casted = reinterpret_cast<const clang::FunctionProtoType *>(self);
    return bitcast(casted->getReturnType());
}

ZigClangCompoundStmt_const_body_iterator ZigClangCompoundStmt_body_begin(const struct ZigClangCompoundStmt *self) {
    auto casted = reinterpret_cast<const clang::CompoundStmt *>(self);
    return bitcast(casted->body_begin());
}

ZigClangCompoundStmt_const_body_iterator ZigClangCompoundStmt_body_end(const struct ZigClangCompoundStmt *self) {
    auto casted = reinterpret_cast<const clang::CompoundStmt *>(self);
    return bitcast(casted->body_end());
}

ZigClangDeclStmt_const_decl_iterator ZigClangDeclStmt_decl_begin(const struct ZigClangDeclStmt *self) {
    auto casted = reinterpret_cast<const clang::DeclStmt *>(self);
    return bitcast(casted->decl_begin());
}

ZigClangDeclStmt_const_decl_iterator ZigClangDeclStmt_decl_end(const struct ZigClangDeclStmt *self) {
    auto casted = reinterpret_cast<const clang::DeclStmt *>(self);
    return bitcast(casted->decl_end());
}

ZigClangSourceLocation ZigClangDeclStmt_getBeginLoc(const struct ZigClangDeclStmt *self) {
    auto casted = reinterpret_cast<const clang::DeclStmt *>(self);
    return bitcast(casted->getBeginLoc());
}

unsigned ZigClangAPFloat_convertToHexString(const ZigClangAPFloat *self, char *DST,
        unsigned HexDigits, bool UpperCase, enum ZigClangAPFloat_roundingMode RM)
{
    auto casted = reinterpret_cast<const llvm::APFloat *>(self);
    return casted->convertToHexString(DST, HexDigits, UpperCase, (llvm::APFloat::roundingMode)RM);
}

double ZigClangFloatingLiteral_getValueAsApproximateDouble(const ZigClangFloatingLiteral *self) {
    auto casted = reinterpret_cast<const clang::FloatingLiteral *>(self);
    return casted->getValueAsApproximateDouble();
}

ZigClangAPFloatBase_Semantics ZigClangFloatingLiteral_getRawSemantics(const ZigClangFloatingLiteral *self) {
    auto casted = reinterpret_cast<const clang::FloatingLiteral *>(self);
    return static_cast<ZigClangAPFloatBase_Semantics>(casted->getRawSemantics());
}

enum ZigClangStringLiteral_StringKind ZigClangStringLiteral_getKind(const struct ZigClangStringLiteral *self) {
    auto casted = reinterpret_cast<const clang::StringLiteral *>(self);
    return (ZigClangStringLiteral_StringKind)casted->getKind();
}

uint32_t ZigClangStringLiteral_getCodeUnit(const struct ZigClangStringLiteral *self, size_t i) {
    auto casted = reinterpret_cast<const clang::StringLiteral *>(self);
    return casted->getCodeUnit(i);
}

unsigned ZigClangStringLiteral_getLength(const struct ZigClangStringLiteral *self) {
    auto casted = reinterpret_cast<const clang::StringLiteral *>(self);
    return casted->getLength();
}

unsigned ZigClangStringLiteral_getCharByteWidth(const struct ZigClangStringLiteral *self) {
    auto casted = reinterpret_cast<const clang::StringLiteral *>(self);
    return casted->getCharByteWidth();
}

const char *ZigClangStringLiteral_getString_bytes_begin_size(const struct ZigClangStringLiteral *self, size_t *len) {
    auto casted = reinterpret_cast<const clang::StringLiteral *>(self);
    llvm::StringRef str_ref = casted->getString();
    *len = str_ref.size();
    return (const char *)str_ref.bytes_begin();
}

const struct ZigClangStringLiteral *ZigClangPredefinedExpr_getFunctionName(
        const struct ZigClangPredefinedExpr *self)
{
    auto casted = reinterpret_cast<const clang::PredefinedExpr *>(self);
    const clang::StringLiteral *result = casted->getFunctionName();
    return reinterpret_cast<const struct ZigClangStringLiteral *>(result);
}

ZigClangSourceLocation ZigClangImplicitCastExpr_getBeginLoc(const struct ZigClangImplicitCastExpr *self) {
    auto casted = reinterpret_cast<const clang::ImplicitCastExpr *>(self);
    return bitcast(casted->getBeginLoc());
}

enum ZigClangCK ZigClangImplicitCastExpr_getCastKind(const struct ZigClangImplicitCastExpr *self) {
    auto casted = reinterpret_cast<const clang::ImplicitCastExpr *>(self);
    return (ZigClangCK)casted->getCastKind();
}

const struct ZigClangExpr *ZigClangImplicitCastExpr_getSubExpr(const struct ZigClangImplicitCastExpr *self) {
    auto casted = reinterpret_cast<const clang::ImplicitCastExpr *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getSubExpr());
}

struct ZigClangQualType ZigClangArrayType_getElementType(const struct ZigClangArrayType *self) {
    auto casted = reinterpret_cast<const clang::ArrayType *>(self);
    return bitcast(casted->getElementType());
}

struct ZigClangQualType ZigClangIncompleteArrayType_getElementType(const struct ZigClangIncompleteArrayType *self) {
    auto casted = reinterpret_cast<const clang::IncompleteArrayType *>(self);
    return bitcast(casted->getElementType());
}

struct ZigClangQualType ZigClangConstantArrayType_getElementType(const struct ZigClangConstantArrayType *self) {
    auto casted = reinterpret_cast<const clang::ConstantArrayType *>(self);
    return bitcast(casted->getElementType());
}

const struct ZigClangAPInt *ZigClangConstantArrayType_getSize(const struct ZigClangConstantArrayType *self) {
    auto casted = reinterpret_cast<const clang::ConstantArrayType *>(self);
    return reinterpret_cast<const ZigClangAPInt *>(&casted->getSize());
}

const struct ZigClangValueDecl *ZigClangDeclRefExpr_getDecl(const struct ZigClangDeclRefExpr *self) {
    auto casted = reinterpret_cast<const clang::DeclRefExpr *>(self);
    return reinterpret_cast<const struct ZigClangValueDecl *>(casted->getDecl());
}

const struct ZigClangNamedDecl *ZigClangDeclRefExpr_getFoundDecl(const struct ZigClangDeclRefExpr *self) {
    auto casted = reinterpret_cast<const clang::DeclRefExpr *>(self);
    return reinterpret_cast<const struct ZigClangNamedDecl *>(casted->getFoundDecl());
}

struct ZigClangQualType ZigClangParenType_getInnerType(const struct ZigClangParenType *self) {
    auto casted = reinterpret_cast<const clang::ParenType *>(self);
    return bitcast(casted->getInnerType());
}

struct ZigClangQualType ZigClangAttributedType_getEquivalentType(const struct ZigClangAttributedType *self) {
    auto casted = reinterpret_cast<const clang::AttributedType *>(self);
    return bitcast(casted->getEquivalentType());
}

struct ZigClangQualType ZigClangMacroQualifiedType_getModifiedType(const struct ZigClangMacroQualifiedType *self) {
    auto casted = reinterpret_cast<const clang::MacroQualifiedType *>(self);
    return bitcast(casted->getModifiedType());
}

struct ZigClangQualType ZigClangTypeOfType_getUnderlyingType(const struct ZigClangTypeOfType *self) {
    auto casted = reinterpret_cast<const clang::TypeOfType *>(self);
    return bitcast(casted->getUnderlyingType());
}

const struct ZigClangExpr *ZigClangTypeOfExprType_getUnderlyingExpr(const struct ZigClangTypeOfExprType *self) {
    auto casted = reinterpret_cast<const clang::TypeOfExprType *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getUnderlyingExpr());
}

enum ZigClangOffsetOfNode_Kind ZigClangOffsetOfNode_getKind(const struct ZigClangOffsetOfNode *self) {
    auto casted = reinterpret_cast<const clang::OffsetOfNode *>(self);
    return (ZigClangOffsetOfNode_Kind)casted->getKind();
}

unsigned ZigClangOffsetOfNode_getArrayExprIndex(const struct ZigClangOffsetOfNode *self) {
    auto casted = reinterpret_cast<const clang::OffsetOfNode *>(self);
    return casted->getArrayExprIndex();
}

struct ZigClangFieldDecl *ZigClangOffsetOfNode_getField(const struct ZigClangOffsetOfNode *self) {
    auto casted = reinterpret_cast<const clang::OffsetOfNode *>(self);
    return reinterpret_cast<ZigClangFieldDecl *>(casted->getField());
}

unsigned ZigClangOffsetOfExpr_getNumComponents(const struct ZigClangOffsetOfExpr *self) {
    auto casted = reinterpret_cast<const clang::OffsetOfExpr *>(self);
    return casted->getNumComponents();
}

unsigned ZigClangOffsetOfExpr_getNumExpressions(const struct ZigClangOffsetOfExpr *self) {
    auto casted = reinterpret_cast<const clang::OffsetOfExpr *>(self);
    return casted->getNumExpressions();
}

const struct ZigClangExpr *ZigClangOffsetOfExpr_getIndexExpr(const struct ZigClangOffsetOfExpr *self, unsigned idx) {
    auto casted = reinterpret_cast<const clang::OffsetOfExpr *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getIndexExpr(idx));
}

const struct ZigClangOffsetOfNode *ZigClangOffsetOfExpr_getComponent(const struct ZigClangOffsetOfExpr *self, unsigned idx) {
    auto casted = reinterpret_cast<const clang::OffsetOfExpr *>(self);
    return reinterpret_cast<const struct ZigClangOffsetOfNode *>(&casted->getComponent(idx));
}

ZigClangSourceLocation ZigClangOffsetOfExpr_getBeginLoc(const ZigClangOffsetOfExpr *self) {
    auto casted = reinterpret_cast<const clang::OffsetOfExpr *>(self);
    return bitcast(casted->getBeginLoc());
}

struct ZigClangQualType ZigClangElaboratedType_getNamedType(const struct ZigClangElaboratedType *self) {
    auto casted = reinterpret_cast<const clang::ElaboratedType *>(self);
    return bitcast(casted->getNamedType());
}

enum ZigClangElaboratedTypeKeyword ZigClangElaboratedType_getKeyword(const struct ZigClangElaboratedType *self) {
    auto casted = reinterpret_cast<const clang::ElaboratedType *>(self);
    return (ZigClangElaboratedTypeKeyword)casted->getKeyword();
}

struct ZigClangSourceLocation ZigClangCStyleCastExpr_getBeginLoc(const struct ZigClangCStyleCastExpr *self) {
    auto casted = reinterpret_cast<const clang::CStyleCastExpr *>(self);
    return bitcast(casted->getBeginLoc());
}

const struct ZigClangExpr *ZigClangCStyleCastExpr_getSubExpr(const struct ZigClangCStyleCastExpr *self) {
    auto casted = reinterpret_cast<const clang::CStyleCastExpr *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getSubExpr());
}

struct ZigClangQualType ZigClangCStyleCastExpr_getType(const struct ZigClangCStyleCastExpr *self) {
    auto casted = reinterpret_cast<const clang::CStyleCastExpr *>(self);
    return bitcast(casted->getType());
}

const struct ZigClangASTRecordLayout *ZigClangRecordDecl_getASTRecordLayout(const struct ZigClangRecordDecl *self, const struct ZigClangASTContext *ctx) {
    auto casted_self = reinterpret_cast<const clang::RecordDecl *>(self);
    auto casted_ctx = reinterpret_cast<const clang::ASTContext *>(ctx);
    const clang::ASTRecordLayout &layout = casted_ctx->getASTRecordLayout(casted_self);
    return reinterpret_cast<const struct ZigClangASTRecordLayout *>(&layout);
}

uint64_t ZigClangASTRecordLayout_getFieldOffset(const struct ZigClangASTRecordLayout *self, unsigned field_no) {
    return reinterpret_cast<const clang::ASTRecordLayout *>(self)->getFieldOffset(field_no);
}

int64_t ZigClangASTRecordLayout_getAlignment(const struct ZigClangASTRecordLayout *self) {
    auto casted_self = reinterpret_cast<const clang::ASTRecordLayout *>(self);
    return casted_self->getAlignment().getQuantity();
}

bool ZigClangIntegerLiteral_EvaluateAsInt(const struct ZigClangIntegerLiteral *self, struct ZigClangExprEvalResult *result, const struct ZigClangASTContext *ctx) {
    auto casted_self = reinterpret_cast<const clang::IntegerLiteral *>(self);
    auto casted_ctx = reinterpret_cast<const clang::ASTContext *>(ctx);
    clang::Expr::EvalResult eval_result;
    if (!casted_self->EvaluateAsInt(eval_result, *casted_ctx)) {
        return false;
    }
    *result = bitcast(eval_result);
    return true;
}

struct ZigClangSourceLocation ZigClangIntegerLiteral_getBeginLoc(const struct ZigClangIntegerLiteral *self) {
    auto casted = reinterpret_cast<const clang::IntegerLiteral *>(self);
    return bitcast(casted->getBeginLoc());
}

bool ZigClangIntegerLiteral_isZero(const struct ZigClangIntegerLiteral *self, bool *result, const struct ZigClangASTContext *ctx) {
    auto casted_self = reinterpret_cast<const clang::IntegerLiteral *>(self);
    auto casted_ctx = reinterpret_cast<const clang::ASTContext *>(ctx);
    clang::Expr::EvalResult eval_result;
    if (!casted_self->EvaluateAsInt(eval_result, *casted_ctx)) {
        return false;
    }
    const llvm::APSInt result_int = eval_result.Val.getInt();
    const llvm::APSInt zero(result_int.getBitWidth(), result_int.isUnsigned());
    *result = zero == result_int;
    return true;
}

const struct ZigClangExpr *ZigClangReturnStmt_getRetValue(const struct ZigClangReturnStmt *self) {
    auto casted = reinterpret_cast<const clang::ReturnStmt *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getRetValue());
}

enum ZigClangBO ZigClangBinaryOperator_getOpcode(const struct ZigClangBinaryOperator *self) {
    auto casted = reinterpret_cast<const clang::BinaryOperator *>(self);
    return (ZigClangBO)casted->getOpcode();
}

struct ZigClangSourceLocation ZigClangBinaryOperator_getBeginLoc(const struct ZigClangBinaryOperator *self) {
    auto casted = reinterpret_cast<const clang::BinaryOperator *>(self);
    return bitcast(casted->getBeginLoc());
}

const struct ZigClangExpr *ZigClangBinaryOperator_getLHS(const struct ZigClangBinaryOperator *self) {
    auto casted = reinterpret_cast<const clang::BinaryOperator *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getLHS());
}

const struct ZigClangExpr *ZigClangBinaryOperator_getRHS(const struct ZigClangBinaryOperator *self) {
    auto casted = reinterpret_cast<const clang::BinaryOperator *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getRHS());
}

struct ZigClangQualType ZigClangBinaryOperator_getType(const struct ZigClangBinaryOperator *self) {
    auto casted = reinterpret_cast<const clang::BinaryOperator *>(self);
    return bitcast(casted->getType());
}

const struct ZigClangExpr *ZigClangConvertVectorExpr_getSrcExpr(const struct ZigClangConvertVectorExpr *self) {
    auto casted = reinterpret_cast<const clang::ConvertVectorExpr *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getSrcExpr());
}

struct ZigClangQualType ZigClangConvertVectorExpr_getTypeSourceInfo_getType(const struct ZigClangConvertVectorExpr *self) {
    auto casted = reinterpret_cast<const clang::ConvertVectorExpr *>(self);
    return bitcast(casted->getTypeSourceInfo()->getType());
}

struct ZigClangQualType ZigClangDecayedType_getDecayedType(const struct ZigClangDecayedType *self) {
    auto casted = reinterpret_cast<const clang::DecayedType *>(self);
    return bitcast(casted->getDecayedType());
}

const struct ZigClangCompoundStmt *ZigClangStmtExpr_getSubStmt(const struct ZigClangStmtExpr *self) {
    auto casted = reinterpret_cast<const clang::StmtExpr *>(self);
    return reinterpret_cast<const ZigClangCompoundStmt *>(casted->getSubStmt());
}

struct ZigClangSourceLocation ZigClangCharacterLiteral_getBeginLoc(const struct ZigClangCharacterLiteral *self) {
    auto casted = reinterpret_cast<const clang::CharacterLiteral *>(self);
    return bitcast(casted->getBeginLoc());
}

enum ZigClangCharacterLiteral_CharacterKind ZigClangCharacterLiteral_getKind(const struct ZigClangCharacterLiteral *self) {
    auto casted = reinterpret_cast<const clang::CharacterLiteral *>(self);
    return (ZigClangCharacterLiteral_CharacterKind)casted->getKind();
}

unsigned ZigClangCharacterLiteral_getValue(const struct ZigClangCharacterLiteral *self) {
    auto casted = reinterpret_cast<const clang::CharacterLiteral *>(self);
    return casted->getValue();
}

const struct ZigClangExpr *ZigClangAbstractConditionalOperator_getCond(const struct ZigClangAbstractConditionalOperator *self) {
    auto casted = reinterpret_cast<const clang::AbstractConditionalOperator *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getCond());
}

const struct ZigClangExpr *ZigClangAbstractConditionalOperator_getTrueExpr(const struct ZigClangAbstractConditionalOperator *self) {
    auto casted = reinterpret_cast<const clang::AbstractConditionalOperator *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getTrueExpr());
}

const struct ZigClangExpr *ZigClangAbstractConditionalOperator_getFalseExpr(const struct ZigClangAbstractConditionalOperator *self) {
    auto casted = reinterpret_cast<const clang::AbstractConditionalOperator *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getFalseExpr());
}

struct ZigClangQualType ZigClangCompoundAssignOperator_getType(const struct ZigClangCompoundAssignOperator *self) {
    auto casted = reinterpret_cast<const clang::CompoundAssignOperator *>(self);
    return bitcast(casted->getType());
}

struct ZigClangQualType ZigClangCompoundAssignOperator_getComputationLHSType(const struct ZigClangCompoundAssignOperator *self) {
    auto casted = reinterpret_cast<const clang::CompoundAssignOperator *>(self);
    return bitcast(casted->getComputationLHSType());
}

struct ZigClangQualType ZigClangCompoundAssignOperator_getComputationResultType(const struct ZigClangCompoundAssignOperator *self) {
    auto casted = reinterpret_cast<const clang::CompoundAssignOperator *>(self);
    return bitcast(casted->getComputationResultType());
}

struct ZigClangSourceLocation ZigClangCompoundAssignOperator_getBeginLoc(const struct ZigClangCompoundAssignOperator *self) {
    auto casted = reinterpret_cast<const clang::CompoundAssignOperator *>(self);
    return bitcast(casted->getBeginLoc());
}

enum ZigClangBO ZigClangCompoundAssignOperator_getOpcode(const struct ZigClangCompoundAssignOperator *self) {
    auto casted = reinterpret_cast<const clang::CompoundAssignOperator *>(self);
    return (ZigClangBO)casted->getOpcode();
}

const struct ZigClangExpr *ZigClangCompoundAssignOperator_getLHS(const struct ZigClangCompoundAssignOperator *self) {
    auto casted = reinterpret_cast<const clang::CompoundAssignOperator *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getLHS());
}

const struct ZigClangExpr *ZigClangCompoundAssignOperator_getRHS(const struct ZigClangCompoundAssignOperator *self) {
    auto casted = reinterpret_cast<const clang::CompoundAssignOperator *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getRHS());
}

const struct ZigClangExpr *ZigClangCompoundLiteralExpr_getInitializer(const ZigClangCompoundLiteralExpr *self) {
    auto casted = reinterpret_cast<const clang::CompoundLiteralExpr *>(self);
    return reinterpret_cast<const ZigClangExpr *>(casted->getInitializer());
}

enum ZigClangUO ZigClangUnaryOperator_getOpcode(const struct ZigClangUnaryOperator *self) {
    auto casted = reinterpret_cast<const clang::UnaryOperator *>(self);
    return (ZigClangUO)casted->getOpcode();
}

struct ZigClangQualType ZigClangUnaryOperator_getType(const struct ZigClangUnaryOperator *self) {
    auto casted = reinterpret_cast<const clang::UnaryOperator *>(self);
    return bitcast(casted->getType());
}

const struct ZigClangExpr *ZigClangUnaryOperator_getSubExpr(const struct ZigClangUnaryOperator *self) {
    auto casted = reinterpret_cast<const clang::UnaryOperator *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getSubExpr());
}

struct ZigClangSourceLocation ZigClangUnaryOperator_getBeginLoc(const struct ZigClangUnaryOperator *self) {
    auto casted = reinterpret_cast<const clang::UnaryOperator *>(self);
    return bitcast(casted->getBeginLoc());
}

struct ZigClangQualType ZigClangValueDecl_getType(const struct ZigClangValueDecl *self) {
    auto casted = reinterpret_cast<const clang::ValueDecl *>(self);
    return bitcast(casted->getType());
}

struct ZigClangQualType ZigClangVectorType_getElementType(const struct ZigClangVectorType *self) {
    auto casted = reinterpret_cast<const clang::VectorType *>(self);
    return bitcast(casted->getElementType());
}

unsigned ZigClangVectorType_getNumElements(const struct ZigClangVectorType *self) {
    auto casted = reinterpret_cast<const clang::VectorType *>(self);
    return casted->getNumElements();
}

const struct ZigClangExpr *ZigClangWhileStmt_getCond(const struct ZigClangWhileStmt *self) {
    auto casted = reinterpret_cast<const clang::WhileStmt *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getCond());
}

const struct ZigClangStmt *ZigClangWhileStmt_getBody(const struct ZigClangWhileStmt *self) {
    auto casted = reinterpret_cast<const clang::WhileStmt *>(self);
    return reinterpret_cast<const struct ZigClangStmt *>(casted->getBody());
}

const struct ZigClangStmt *ZigClangIfStmt_getThen(const struct ZigClangIfStmt *self) {
    auto casted = reinterpret_cast<const clang::IfStmt *>(self);
    return reinterpret_cast<const struct ZigClangStmt *>(casted->getThen());
}

const struct ZigClangStmt *ZigClangIfStmt_getElse(const struct ZigClangIfStmt *self) {
    auto casted = reinterpret_cast<const clang::IfStmt *>(self);
    return reinterpret_cast<const struct ZigClangStmt *>(casted->getElse());
}

const struct ZigClangExpr *ZigClangIfStmt_getCond(const struct ZigClangIfStmt *self) {
    auto casted = reinterpret_cast<const clang::IfStmt *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getCond());
}

const struct ZigClangExpr *ZigClangCallExpr_getCallee(const struct ZigClangCallExpr *self) {
    auto casted = reinterpret_cast<const clang::CallExpr *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getCallee());
}

unsigned ZigClangCallExpr_getNumArgs(const struct ZigClangCallExpr *self) {
    auto casted = reinterpret_cast<const clang::CallExpr *>(self);
    return casted->getNumArgs();
}

const struct ZigClangExpr * const * ZigClangCallExpr_getArgs(const struct ZigClangCallExpr *self) {
    auto casted = reinterpret_cast<const clang::CallExpr *>(self);
    return reinterpret_cast<const struct ZigClangExpr * const*>(casted->getArgs());
}

const struct ZigClangExpr * ZigClangMemberExpr_getBase(const struct ZigClangMemberExpr *self) {
    auto casted = reinterpret_cast<const clang::MemberExpr *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getBase());
}

bool ZigClangMemberExpr_isArrow(const struct ZigClangMemberExpr *self) {
    auto casted = reinterpret_cast<const clang::MemberExpr *>(self);
    return casted->isArrow();
}

const struct ZigClangValueDecl * ZigClangMemberExpr_getMemberDecl(const struct ZigClangMemberExpr *self) {
    auto casted = reinterpret_cast<const clang::MemberExpr *>(self);
    return reinterpret_cast<const struct ZigClangValueDecl *>(casted->getMemberDecl());
}

const struct ZigClangExpr *ZigClangArraySubscriptExpr_getBase(const struct ZigClangArraySubscriptExpr *self) {
    auto casted = reinterpret_cast<const clang::ArraySubscriptExpr *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getBase());
}

const struct ZigClangExpr *ZigClangArraySubscriptExpr_getIdx(const struct ZigClangArraySubscriptExpr *self) {
    auto casted = reinterpret_cast<const clang::ArraySubscriptExpr *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getIdx());
}

struct ZigClangQualType ZigClangUnaryExprOrTypeTraitExpr_getTypeOfArgument(
        const struct ZigClangUnaryExprOrTypeTraitExpr *self)
{
    auto casted = reinterpret_cast<const clang::UnaryExprOrTypeTraitExpr *>(self);
    return bitcast(casted->getTypeOfArgument());
}

struct ZigClangSourceLocation ZigClangUnaryExprOrTypeTraitExpr_getBeginLoc(
        const struct ZigClangUnaryExprOrTypeTraitExpr *self)
{
    auto casted = reinterpret_cast<const clang::UnaryExprOrTypeTraitExpr *>(self);
    return bitcast(casted->getBeginLoc());
}

unsigned ZigClangShuffleVectorExpr_getNumSubExprs(const ZigClangShuffleVectorExpr *self) {
    auto casted = reinterpret_cast<const clang::ShuffleVectorExpr *>(self);
    return casted->getNumSubExprs();
}

const struct ZigClangExpr *ZigClangShuffleVectorExpr_getExpr(const struct ZigClangShuffleVectorExpr *self, unsigned idx) {
    auto casted = reinterpret_cast<const clang::ShuffleVectorExpr *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getExpr(idx));
}

enum ZigClangUnaryExprOrTypeTrait_Kind ZigClangUnaryExprOrTypeTraitExpr_getKind(
    const struct ZigClangUnaryExprOrTypeTraitExpr *self)
{
    auto casted = reinterpret_cast<const clang::UnaryExprOrTypeTraitExpr *>(self);
    return (ZigClangUnaryExprOrTypeTrait_Kind)casted->getKind();
}

const struct ZigClangStmt *ZigClangDoStmt_getBody(const struct ZigClangDoStmt *self) {
    auto casted = reinterpret_cast<const clang::DoStmt *>(self);
    return reinterpret_cast<const struct ZigClangStmt *>(casted->getBody());
}

const struct ZigClangExpr *ZigClangDoStmt_getCond(const struct ZigClangDoStmt *self) {
    auto casted = reinterpret_cast<const clang::DoStmt *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getCond());
}

const struct ZigClangStmt *ZigClangForStmt_getInit(const struct ZigClangForStmt *self) {
    auto casted = reinterpret_cast<const clang::ForStmt *>(self);
    return reinterpret_cast<const struct ZigClangStmt *>(casted->getInit());
}

const struct ZigClangExpr *ZigClangForStmt_getCond(const struct ZigClangForStmt *self) {
    auto casted = reinterpret_cast<const clang::ForStmt *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getCond());
}

const struct ZigClangExpr *ZigClangForStmt_getInc(const struct ZigClangForStmt *self) {
    auto casted = reinterpret_cast<const clang::ForStmt *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getInc());
}

const struct ZigClangStmt *ZigClangForStmt_getBody(const struct ZigClangForStmt *self) {
    auto casted = reinterpret_cast<const clang::ForStmt *>(self);
    return reinterpret_cast<const struct ZigClangStmt *>(casted->getBody());
}

const struct ZigClangDeclStmt *ZigClangSwitchStmt_getConditionVariableDeclStmt(
        const struct ZigClangSwitchStmt *self)
{
    auto casted = reinterpret_cast<const clang::SwitchStmt *>(self);
    return reinterpret_cast<const struct ZigClangDeclStmt *>(casted->getConditionVariableDeclStmt());
}

const struct ZigClangExpr *ZigClangSwitchStmt_getCond(const struct ZigClangSwitchStmt *self) {
    auto casted = reinterpret_cast<const clang::SwitchStmt *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getCond());
}

const struct ZigClangStmt *ZigClangSwitchStmt_getBody(const struct ZigClangSwitchStmt *self) {
    auto casted = reinterpret_cast<const clang::SwitchStmt *>(self);
    return reinterpret_cast<const struct ZigClangStmt *>(casted->getBody());
}

bool ZigClangSwitchStmt_isAllEnumCasesCovered(const struct ZigClangSwitchStmt *self) {
    auto casted = reinterpret_cast<const clang::SwitchStmt *>(self);
    return casted->isAllEnumCasesCovered();
}

const struct ZigClangExpr *ZigClangCaseStmt_getLHS(const struct ZigClangCaseStmt *self) {
    auto casted = reinterpret_cast<const clang::CaseStmt *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getLHS());
}

const struct ZigClangExpr *ZigClangCaseStmt_getRHS(const struct ZigClangCaseStmt *self) {
    auto casted = reinterpret_cast<const clang::CaseStmt *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getRHS());
}

struct ZigClangSourceLocation ZigClangCaseStmt_getBeginLoc(const struct ZigClangCaseStmt *self) {
    auto casted = reinterpret_cast<const clang::CaseStmt *>(self);
    return bitcast(casted->getBeginLoc());
}

const struct ZigClangStmt *ZigClangCaseStmt_getSubStmt(const struct ZigClangCaseStmt *self) {
    auto casted = reinterpret_cast<const clang::CaseStmt *>(self);
    return reinterpret_cast<const struct ZigClangStmt *>(casted->getSubStmt());
}

const struct ZigClangStmt *ZigClangDefaultStmt_getSubStmt(const struct ZigClangDefaultStmt *self) {
    auto casted = reinterpret_cast<const clang::DefaultStmt *>(self);
    return reinterpret_cast<const struct ZigClangStmt *>(casted->getSubStmt());
}

const struct ZigClangExpr *ZigClangParenExpr_getSubExpr(const struct ZigClangParenExpr *self) {
    auto casted = reinterpret_cast<const clang::ParenExpr *>(self);
    return reinterpret_cast<const struct ZigClangExpr *>(casted->getSubExpr());
}

enum ZigClangPreprocessedEntity_EntityKind ZigClangPreprocessedEntity_getKind(
        const struct ZigClangPreprocessedEntity *self)
{
    auto casted = reinterpret_cast<const clang::PreprocessedEntity *>(self);
    return (ZigClangPreprocessedEntity_EntityKind)casted->getKind();
}

const char *ZigClangMacroDefinitionRecord_getName_getNameStart(const struct ZigClangMacroDefinitionRecord *self) {
    auto casted = reinterpret_cast<const clang::MacroDefinitionRecord *>(self);
    return casted->getName()->getNameStart();
}

struct ZigClangSourceLocation ZigClangMacroDefinitionRecord_getSourceRange_getBegin(const struct ZigClangMacroDefinitionRecord *self) {
    auto casted = reinterpret_cast<const clang::MacroDefinitionRecord *>(self);
    return bitcast(casted->getSourceRange().getBegin());
}

struct ZigClangSourceLocation ZigClangMacroDefinitionRecord_getSourceRange_getEnd(const struct ZigClangMacroDefinitionRecord *self) {
    auto casted = reinterpret_cast<const clang::MacroDefinitionRecord *>(self);
    return bitcast(casted->getSourceRange().getEnd());
}

struct ZigClangSourceLocation ZigClangLexer_getLocForEndOfToken(ZigClangSourceLocation loc, const ZigClangSourceManager *sm, const ZigClangASTUnit *unit) {
    const clang::SourceManager *casted_sm = reinterpret_cast<const clang::SourceManager *>(sm);
    const clang::ASTUnit *casted_unit = reinterpret_cast<const clang::ASTUnit *>(unit);
    clang::SourceLocation endloc = clang::Lexer::getLocForEndOfToken(bitcast(loc), 0, *casted_sm, casted_unit->getLangOpts());
    return bitcast(endloc);
}

ZigClangRecordDecl_field_iterator ZigClangRecordDecl_field_begin(const struct ZigClangRecordDecl *self) {
    auto casted = reinterpret_cast<const clang::RecordDecl *>(self);
    return bitcast(casted->field_begin());
}

ZigClangRecordDecl_field_iterator ZigClangRecordDecl_field_end(const struct ZigClangRecordDecl *self) {
    auto casted = reinterpret_cast<const clang::RecordDecl *>(self);
    return bitcast(casted->field_end());
}

bool ZigClangFieldDecl_isBitField(const struct ZigClangFieldDecl *self) {
    auto casted = reinterpret_cast<const clang::FieldDecl *>(self);
    return casted->isBitField();
}

bool ZigClangFieldDecl_isAnonymousStructOrUnion(const ZigClangFieldDecl *field_decl) {
    return reinterpret_cast<const clang::FieldDecl*>(field_decl)->isAnonymousStructOrUnion();
}

ZigClangSourceLocation ZigClangFieldDecl_getLocation(const struct ZigClangFieldDecl *self) {
    auto casted = reinterpret_cast<const clang::FieldDecl *>(self);
    return bitcast(casted->getLocation());
}

const struct ZigClangRecordDecl *ZigClangFieldDecl_getParent(const struct ZigClangFieldDecl *self) {
    auto casted = reinterpret_cast<const clang::FieldDecl *>(self);
    return reinterpret_cast<const ZigClangRecordDecl *>(casted->getParent());
}

unsigned ZigClangFieldDecl_getFieldIndex(const struct ZigClangFieldDecl *self) {
    auto casted = reinterpret_cast<const clang::FieldDecl *>(self);
    return casted->getFieldIndex();
}

ZigClangQualType ZigClangFieldDecl_getType(const struct ZigClangFieldDecl *self) {
    auto casted = reinterpret_cast<const clang::FieldDecl *>(self);
    return bitcast(casted->getType());
}

ZigClangRecordDecl_field_iterator ZigClangRecordDecl_field_iterator_next(
        struct ZigClangRecordDecl_field_iterator self)
{
    clang::RecordDecl::field_iterator casted = bitcast(self);
    ++casted;
    return bitcast(casted);
}

const struct ZigClangFieldDecl * ZigClangRecordDecl_field_iterator_deref(
        struct ZigClangRecordDecl_field_iterator self)
{
    clang::RecordDecl::field_iterator casted = bitcast(self);
    const clang::FieldDecl *result = *casted;
    return reinterpret_cast<const ZigClangFieldDecl *>(result);
}

bool ZigClangRecordDecl_field_iterator_neq(
        struct ZigClangRecordDecl_field_iterator a,
        struct ZigClangRecordDecl_field_iterator b)
{
    clang::RecordDecl::field_iterator casted_a = bitcast(a);
    clang::RecordDecl::field_iterator casted_b = bitcast(b);
    return casted_a != casted_b;
}

ZigClangEnumDecl_enumerator_iterator ZigClangEnumDecl_enumerator_begin(const struct ZigClangEnumDecl *self) {
    auto casted = reinterpret_cast<const clang::EnumDecl *>(self);
    return bitcast(casted->enumerator_begin());
}

ZigClangEnumDecl_enumerator_iterator ZigClangEnumDecl_enumerator_end(const struct ZigClangEnumDecl *self) {
    auto casted = reinterpret_cast<const clang::EnumDecl *>(self);
    return bitcast(casted->enumerator_end());
}

ZigClangEnumDecl_enumerator_iterator ZigClangEnumDecl_enumerator_iterator_next(
        struct ZigClangEnumDecl_enumerator_iterator self)
{
    clang::EnumDecl::enumerator_iterator casted = bitcast(self);
    ++casted;
    return bitcast(casted);
}

const struct ZigClangEnumConstantDecl * ZigClangEnumDecl_enumerator_iterator_deref(
        struct ZigClangEnumDecl_enumerator_iterator self)
{
    clang::EnumDecl::enumerator_iterator casted = bitcast(self);
    const clang::EnumConstantDecl *result = *casted;
    return reinterpret_cast<const ZigClangEnumConstantDecl *>(result);
}

bool ZigClangEnumDecl_enumerator_iterator_neq(
        struct ZigClangEnumDecl_enumerator_iterator a,
        struct ZigClangEnumDecl_enumerator_iterator b)
{
    clang::EnumDecl::enumerator_iterator casted_a = bitcast(a);
    clang::EnumDecl::enumerator_iterator casted_b = bitcast(b);
    return casted_a != casted_b;
}

const struct ZigClangAPSInt *ZigClangEnumConstantDecl_getInitVal(const struct ZigClangEnumConstantDecl *self) {
    auto casted = reinterpret_cast<const clang::EnumConstantDecl *>(self);
    const llvm::APSInt *result = &casted->getInitVal();
    return reinterpret_cast<const ZigClangAPSInt *>(result);
}
