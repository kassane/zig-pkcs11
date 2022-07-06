const std = @import("std");
const pkcs11 = @import("pkcs11.zig");
const pkcs11t = @import("pkcs11t.zig");
const pkcs11f = @import("pkcs11f.zig");
const crypto = std.crypto;
const dyn = std.DynLib;
const testing = std.testing;

// pub export fn New(arg_module: [*:0]const u8) pkcs11.Context {
//     var module = arg_module;
//     var list: CK_C_GetFunctionList = undefined;
//     var c: [*c]Context = @ptrCast([*c]Context, @alignCast(@import("std").meta.alignment(Context), calloc(@bitCast(c_ulong, @as(c_long, @as(c_int, 1))), @sizeOf(Context))));
//     c.*.handle = dlopen(module, @as(c_int, 1));
//     if (c.*.handle == @intToPtr(?*anyopaque, @as(c_int, 0))) {
//         free(@ptrCast(?*anyopaque, c));
//         return null;
//     }
//     list = @ptrCast(CK_C_GetFunctionList, @alignCast(@import("std").meta.alignment(fn (CK_FUNCTION_LIST_PTR_PTR) callconv(.C) CK_RV), dlsym(c.*.handle, "C_GetFunctionList")));
//     if (list == @ptrCast(CK_C_GetFunctionList, @alignCast(@import("std").meta.alignment(fn (CK_FUNCTION_LIST_PTR_PTR) callconv(.C) CK_RV), @intToPtr(?*anyopaque, @as(c_int, 0))))) {
//         free(@ptrCast(?*anyopaque, c));
//         return null;
//     }
//     _ = list.?(&c.*.sym);
//     return c;
// }

test "Detecting libsoftHSM2" {
    // embedded lib on compilation time
    // _ = @embedFile("/usr/lib/softhsm/libsofthsm2.so");
    var libname = "/usr/lib/softhsm/libsofthsm2.so";
    _ = dyn.open(libname) catch |err| {
        try testing.expect(err == error.FileNotFound);
        return;
    };
}

test "Reference all the declarations" {
    testing.refAllDecls(pkcs11);
    testing.refAllDecls(@This());
}
