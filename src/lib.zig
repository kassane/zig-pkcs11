const std = @import("std");
const types = @import("pkcs11t.zig");
const testing = std.testing;

test {
    _ = @import("pkcs11t.zig");
    _ = @import("pkcs11f.zig");
}

test "softHSM" {
    const lib = @embedFile("/usr/lib/softhsm/libsofthsm2.so");
    _ = lib;
}
