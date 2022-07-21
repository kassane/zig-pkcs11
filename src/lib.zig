const std = @import("std");
const pkcs11 = @import("pkcs11.zig");
const crypto = std.crypto;
const dyn = std.DynLib;
const testing = std.testing;

test "Detecting libsoftHSM2" {
    // embedded lib on compilation time
    _ = @embedFile("/usr/lib/softhsm/libsofthsm2.so");
}

test "Reference all the declarations" {
    testing.refAllDecls(pkcs11);
    testing.refAllDecls(@This());
}
