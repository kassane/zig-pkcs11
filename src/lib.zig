const std = @import("std");
const pkcs11 = @import("pkcs11.zig");
const testing = std.testing;

test "softHSM2" {
    const lib = @embedFile("/usr/lib/softhsm/libsofthsm2.so");
    _ = lib;
}

test "Reference all the declarations" {
    testing.refAllDecls(pkcs11);
    testing.refAllDecls(@This());
}
