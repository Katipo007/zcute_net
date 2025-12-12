pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const opt_use_llvm = b.option(bool, "use-llvm", "");
    const opt_ipv6_support = b.option(bool, "ipv6-support", "") orelse true;
    const opt_server_max_num_clients = b.option(u16, "server-max-num-clients", "") orelse 32;

    const step_install = b.getInstallStep();
    const step_check = b.step("check", "Compile, but don't emit artifacts.");
    const step_test = b.step("test", "Run the cute_net unit tests.");
    const step_install_tests = b.step("install-tests", "");

    const options = b.addOptions();
    options.addOption(bool, "ipv6_support", opt_ipv6_support);
    options.addOption(c_int, "server_max_num_clients", opt_server_max_num_clients);
    const mod_options = options.createModule();

    if (opt_server_max_num_clients <= 0)
        return error.@"server-max-num-clients must be at least 1";

    //
    // Zig wrapper module
    //

    const mod_zcute_net = b.addModule("zcute_net", .{
        .root_source_file = b.path("src/zcute_net.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    mod_zcute_net.addImport("options", mod_options);
    mod_zcute_net.addIncludePath(b.path("include"));
    mod_zcute_net.addIncludePath(b.path("src"));
    mod_zcute_net.addCSourceFile(.{
        .language = .c,
        .file = b.path("src/zcute_net.c"),
        .flags = bk: {
            const allocator = b.allocator;
            var flags = std.ArrayList([]const u8).empty;
            try flags.appendSlice(allocator, &.{
                "-std=c99",
                "-fno-sanitize=undefined",
                b.fmt("-DCN_SERVER_MAX_CLIENTS={d}", .{opt_server_max_num_clients}),
            });
            if (!opt_ipv6_support)
                try flags.append(allocator, "-DCUTE_NET_NO_IPV6");
            if (optimize == .ReleaseFast)
                try flags.append(allocator, "-DNDEBUG");
            switch (target.result.os.tag) {
                .windows => {
                    try flags.appendSlice(allocator, &.{
                        "-D_WIN32",
                        "-DWIN32_LEAN_AND_MEAN",
                        "-includewindows.h",
                        "-includewinnt.h",
                    });
                },
                .linux => {
                    try flags.append(allocator, if (target.result.abi.isAndroid()) "-D__ANDROID__" else "-D__linux__");
                },
                .macos, .ios, .tvos => {
                    try flags.append(allocator, "-D__APPLE__");
                },
                .emscripten => {
                    try flags.append(allocator, "-D__EMSCRIPTEN__");
                },
                else => {},
            }

            break :bk try flags.toOwnedSlice(allocator);
        },
    });
    if (target.result.os.tag == .windows) {
        mod_zcute_net.linkSystemLibrary("ws2_32", .{ .needed = true });
        mod_zcute_net.linkSystemLibrary("advapi32", .{ .needed = true });
        mod_zcute_net.addCSourceFile(.{
            .language = .c,
            .file = b.path("src/ws2_32.c"),
            .flags = &.{
                "-std=c99",
            },
        });
    }

    //
    // Library
    //
    const lib_zcute_net = b.addLibrary(.{
        .name = "zcute_net",
        .root_module = mod_zcute_net,
        .linkage = .static,
    });
    step_check.dependOn(&lib_zcute_net.step);
    step_install.dependOn(&b.addInstallArtifact(lib_zcute_net, .{}).step);
    //step_install.dependOn(&b.addInstallHeaderFile(lib_zcute_net.getEmittedH(), "zcute_net.h").step);

    //
    // Test Executables
    //
    const exe_zcute_net_tests = b.addTest(.{
        .name = "zcute_net_tests",
        .root_module = mod_zcute_net,
        .use_llvm = opt_use_llvm,
    });
    step_check.dependOn(&exe_zcute_net_tests.step);
    step_test.dependOn(&b.addRunArtifact(exe_zcute_net_tests).step);
    step_install_tests.dependOn(&b.addInstallArtifact(exe_zcute_net_tests, .{}).step);
}

const std = @import("std");
