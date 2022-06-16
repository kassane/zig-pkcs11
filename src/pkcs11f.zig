const pkcs11t = @import("pkcs11t.zig");
pub const func = @cImport({
    @cInclude("pkcs11f.h");
});
