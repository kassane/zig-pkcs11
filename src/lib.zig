const std = @import("std");
const pkcs11 = @import("pkcs11.zig");
const mem = std.mem;
const dyn = std.DynLib;
const log = std.log;
const testing = std.testing;

pub fn getLibP11Path() [*:0]const u8 {
    return "/usr/lib/softhsm/libsofthsm2.so";
}

pub export fn New(module: [*:0]const u8) callconv(.C) ?*pkcs11.Context {
    const library = if (module == "") getLibP11Path() else module;
    var ctx: pkcs11.Context = undefined;

    var lib = dyn.open(mem.sliceTo(library, 0)) catch |err| {
        log.err("\nError: Library {s} can't be load!\nCode: {}\n", .{ library, err });
        return &ctx;
    };
    defer lib.close();

    _ = lib.lookup(@TypeOf(ctx.sym.C_Initialize), "C_Initialize") orelse log.err("\nError: C_Initialize - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_GetInfo), "C_GetInfo") orelse log.err("\nError: C_GetInfo - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_CancelFunction), "C_CancelFunction") orelse log.err("\nError: C_CancelFunction - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_Finalize), "C_Finalize") orelse log.err("\nError: C_Finalize - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_GetFunctionList), "C_GetFunctionList") orelse log.err("\nError: C_GetFunctionList - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_GetSlotList), "C_GetSlotList") orelse log.err("\nError: C_GetSlotList - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_GetSlotInfo), "C_GetSlotInfo") orelse log.err("\nError: C_GetSlotInfo - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_GetTokenInfo), "C_GetTokenInfo") orelse log.err("\nError: C_GetTokenInfo - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_GetMechanismList), "C_GetMechanismList") orelse log.err("\nError: C_GetMechanismList - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_GetMechanismInfo), "C_GetMechanismInfo") orelse log.err("\nError: C_GetMechanismInfo - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_InitToken), "C_InitToken") orelse log.err("\nError: C_InitToken - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_InitPIN), "C_InitPIN") orelse log.err("\nError: C_InitPIN - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_SetPIN), "C_SetPIN") orelse log.err("\nError: C_SetPIN - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_OpenSession), "C_OpenSession") orelse log.err("\nError: C_OpenSession - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_CloseSession), "C_CloseSession") orelse log.err("\nError: C_CloseSession - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_CloseAllSessions), "C_CloseAllSessions") orelse log.err("\nError: C_CloseAllSessions - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_GetSessionInfo), "C_GetSessionInfo") orelse log.err("\nError: C_GetSessionInfo - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_GetOperationState), "C_GetOperationState") orelse log.err("\nError: C_GetOperationState - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_SetOperationState), "C_SetOperationState") orelse log.err("\nError: C_SetOperationState - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_Login), "C_Login") orelse log.err("\nError: C_Login - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_Logout), "C_Logout") orelse log.err("\nError: C_Logout - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_CreateObject), "C_CreateObject") orelse log.err("\nError: C_CreateObject - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_CopyObject), "C_CopyObject") orelse log.err("\nError: C_CopyObject - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_DestroyObject), "C_DestroyObject") orelse log.err("\nError: C_DestroyObject - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_GetObjectSize), "C_GetObjectSize") orelse log.err("\nError: C_GetObjectSize - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_GetAttributeValue), "C_GetAttributeValue") orelse log.err("\nError: C_GetAttributeValue - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_SetAttributeValue), "C_SetAttributeValue") orelse log.err("\nError: C_SetAttributeValue - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_FindObjectsInit), "C_FindObjectsInit") orelse log.err("\nError: C_FindObjectsInit - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_FindObjects), "C_FindObjects") orelse log.err("\nError: C_FindObjects - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_FindObjectsFinal), "C_FindObjectsFinal") orelse log.err("\nError: C_FindObjectsFinal - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_EncryptInit), "C_EncryptInit") orelse log.err("\nError: C_EncryptInit - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_Encrypt), "C_Encrypt") orelse log.err("\nError: C_Encrypt - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_EncryptUpdate), "C_EncryptUpdate") orelse log.err("\nError: C_EncryptUpdate - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_EncryptFinal), "C_EncryptFinal") orelse log.err("\nError: C_EncryptFinal - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_DecryptInit), "C_DecryptInit") orelse log.err("\nError: C_DecryptInit - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_Decrypt), "C_Decrypt") orelse log.err("\nError: C_Decrypt - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_DecryptUpdate), "C_DecryptUpdate") orelse log.err("\nError: C_DecryptUpdate - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_DecryptFinal), "C_DecryptFinal") orelse log.err("\nError: C_DecryptFinal - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_DigestInit), "C_DigestInit") orelse log.err("\nError: C_DigestInit - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_Digest), "C_Digest") orelse log.err("\nError: C_Digest - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_DigestUpdate), "C_DigestUpdate") orelse log.err("\nError: C_DigestUpdate - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_DigestKey), "C_DigestKey") orelse log.err("\nError: C_DigestKey - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_DigestFinal), "C_DigestFinal") orelse log.err("\nError: C_DigestFinal - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_SignInit), "C_SignInit") orelse log.err("\nError: C_SignInit - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_Sign), "C_Sign") orelse log.err("\nError: C_Sign - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_SignUpdate), "C_SignUpdate") orelse log.err("\nError: C_SignUpdate - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_SignFinal), "C_SignFinal") orelse log.err("\nError: C_SignFinal - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_SignRecoverInit), "C_SignRecoverInit") orelse log.err("\nError: C_SignRecoverInit - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_SignRecover), "C_SignRecover") orelse log.err("\nError: C_SignRecover - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_VerifyInit), "C_VerifyInit") orelse log.err("\nError: C_VerifyInit - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_Verify), "C_Verify") orelse log.err("\nError: C_Verify - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_VerifyUpdate), "C_VerifyUpdate") orelse log.err("\nError: C_VerifyUpdate - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_VerifyFinal), "C_VerifyFinal") orelse log.err("\nError: C_VerifyFinal - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_VerifyRecoverInit), "C_VerifyRecoverInit") orelse log.err("\nError: C_VerifyRecoverInit - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_VerifyRecover), "C_VerifyRecover") orelse log.err("\nError: C_VerifyRecover - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_DigestEncryptUpdate), "C_DigestEncryptUpdate") orelse log.err("\nError: C_DigestEncryptUpdate - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_DecryptDigestUpdate), "C_DecryptDigestUpdate") orelse log.err("\nError: C_DecryptDigestUpdate - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_SignEncryptUpdate), "C_SignEncryptUpdate") orelse log.err("\nError: C_SignEncryptUpdate - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_DecryptVerifyUpdate), "C_DecryptVerifyUpdate") orelse log.err("\nError: C_DecryptVerifyUpdate - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_GenerateKey), "C_GenerateKey") orelse log.err("\nError: C_GenerateKey - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_GenerateKeyPair), "C_GenerateKeyPair") orelse log.err("\nError: C_GenerateKeyPair - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_WrapKey), "C_WrapKey") orelse log.err("\nError: C_WrapKey - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_UnwrapKey), "C_UnwrapKey") orelse log.err("\nError: C_UnwrapKey - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_DeriveKey), "C_DeriveKey") orelse log.err("\nError: C_DeriveKey - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_SeedRandom), "C_SeedRandom") orelse log.err("\nError: C_SeedRandom - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_GenerateRandom), "C_GenerateRandom") orelse log.err("\nError: C_GenerateRandom - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_GetFunctionStatus), "C_GetFunctionStatus") orelse log.err("\nError: C_GetFunctionStatus - {}\n", .{error.SymbolNotFound});
    _ = lib.lookup(@TypeOf(ctx.sym.C_WaitForSlotEvent), "C_WaitForSlotEvent") orelse log.err("\nError: C_WaitForSlotEvent - {}\n", .{error.SymbolNotFound});

    return &ctx;
}

pub export fn Finalize(ctx: *pkcs11.Context) callconv(.C) ?*pkcs11.Context {
    return ctx;
}

test "Detecting default libSoftHSM 2" {
    const ctx = New("");
    _ = ctx;
}

// test "Error - lib not found" {
//     const ctx = New("/usr/lib/libp11.so");
//     _ = ctx;
// }

test "Reference all the declarations" {
    // fix error: evaluation exceeded 1000 backwards branches
    if (pkcs11.zig_backend == .stage1) @setEvalBranchQuota(3000); // minimum value

    testing.refAllDeclsRecursive(@This());
    testing.refAllDeclsRecursive(pkcs11);
}
