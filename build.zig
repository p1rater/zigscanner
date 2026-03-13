// build.zig — Zig build system configuration
// Zig's build system is written in Zig, which is elegant
// and also means you have to learn Zig to configure your build.
// Worth it, honestly.

const std = @import("std");

pub fn build(b: *std.Build) void {
    // Standard target options — allows cross-compilation from the command line
    // e.g. zig build -Dtarget=x86_64-windows
    const target = b.standardTargetOptions(.{});

    // Standard optimization options
    // ReleaseFast for production, Debug for development
    // ReleaseSafe is a good middle ground if you're paranoid about safety
    const optimize = b.standardOptimizeOption(.{});

    // Main executable
    const exe = b.addExecutable(.{
        .name = "zigscanner",
        // BURAYA DİKKAT: "src/" ibaresini tamamen kaldır
        .root_source_file = b.path("main.zig"), 
        .target = target,
        .optimize = optimize,
    });

    // Install the executable into the prefix (zig-out/bin/ by default)
    b.installArtifact(exe);

    // `zig build run` — builds and runs in one step
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    // Allow passing arguments: `zig build run -- 192.168.1.1 -p 1-1024`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Build and run zigscanner");
    run_step.dependOn(&run_cmd.step);

    // Unit tests — `zig build test`
    // We don't have many tests yet, but the infrastructure is here
    // Unit tests — `zig build test`
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"), // <--- BURADAKİ src/ HALA DURUYOR!
        .target = target,
        .optimize = optimize,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}

