const builtin = @import("std").builtin;
const types = @import("pkcs11t.zig");

const ctx = switch (builtin.os.tag) {
    .Windows => struct {
        handle: ?@import("std").os.windows.HMODULE,
        sym: types.CK_FUNCTION_LIST_PTR,
    },
    .Linux => struct {
        handle: ?*anyopaque,
        sym: types.CK_FUNCTION_LIST_PTR,
    },
};
