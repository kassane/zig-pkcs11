const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    // Standard target options allow the person running `zig build` to select
    const target = b.standardTargetOptions(.{});

    if (comptime !checkVersion())
        @compileError("Old compiler!");

    // prominent errors are printed to the console, and the build fails.
    b.prominent_compile_errors = true;

    const lib = b.addSharedLibrary("zig-pkcs11", "src/lib.zig", .unversioned);
    lib.setBuildMode(mode);
    lib.setTarget(target);
    lib.install();

    var tests = b.addTest("src/lib.zig");
    tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&tests.step);
}

fn checkVersion() bool {
    if (!@hasDecl(builtin, "zig_version")) {
        return false;
    }

    const needed_version = std.SemanticVersion.parse("0.10.0-dev.4720") catch unreachable;
    const version = builtin.zig_version;
    const order = version.order(needed_version);
    return order != .lt;
}
