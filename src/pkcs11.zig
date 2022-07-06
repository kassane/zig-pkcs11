const builtin = @import("builtin");
const pkcs11t = @import("pkcs11t.zig");
const pkcs11f = @import("pkcs11f.zig");

pub const Context = struct {
    handle: ?*anyopaque,
    sym: pkcs11f.CK_FUNCTION_LIST_PTR,
};

test {
    _ = pkcs11f;
    _ = pkcs11t;
    @import("std").testing.refAllDecls(@This());
}
