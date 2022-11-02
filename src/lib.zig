const std = @import("std");
const pkcs11 = @import("pkcs11.zig");
const crypto = std.crypto;
const mem = std.mem;
const dyn = std.DynLib;
const testing = std.testing;

pub fn getLibP11Path() []const u8 {
    return "/usr/lib/softhsm/libsofthsm2.so";
}

export fn New(module: [*:0]const u8) callconv(.C) ?*pkcs11.Context {
    var ctx: pkcs11.Context = undefined;
    var lib = dyn.open(mem.sliceTo(module, 0)) catch |err| {
        std.log.err("\nError: Library not found!\nCode: {}\n", .{err});
        return &ctx;
    };
    defer lib.close();

    var C_GetInfo = lib.lookup(pkcs11.CK_C_GetInfo, "CK_C_GetInfo");
    ctx.sym.C_GetInfo = C_GetInfo.?.?;
    return &ctx;
}

export fn Finalize(ctx: *pkcs11.Context) callconv(.C) ?*pkcs11.Context {
    return ctx;
}

test "Detecting libSoftHSM 2" {
    // convert []const u8 to [*:0]const u8
    var libname: [getLibP11Path().len:0]u8 = undefined;
    mem.copy(u8, libname[0..libname.len], getLibP11Path());
    libname[getLibP11Path().len] = 0;

    const ctx = New(libname[0..getLibP11Path().len :0]);
    _ = ctx.?.*.sym.C_GetInfo;
}

test "Reference all the declarations" {
    testing.refAllDeclsRecursive(@This());
}
