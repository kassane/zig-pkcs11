const builtin = @import("std").builtin;
const pkcs11t = @import("pkcs11t.zig");
const pkcs11f = @import("pkcs11f.zig");

const ctx = switch (builtin.os.tag) {
    .Windows => struct {
        handle: ?@import("std").os.windows.HMODULE,
        sym: pkcs11t.CK_FUNCTION_LIST_PTR,
    },
    .Linux => struct {
        handle: ?*anyopaque,
        sym: pkcs11t.CK_FUNCTION_LIST_PTR,
    },
};

test {
    _ = pkcs11f;
    _ = pkcs11t;
}
