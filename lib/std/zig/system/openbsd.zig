const builtin = @import("builtin");
const std = @import("std");

const native_arch = builtin.target.cpu.arch;

const aarch64 = struct {
    fn sysctlReg(key: c_int) ?u64 {
        const mib: [2]c_int = [_]c_int{
            std.c.CTL.MACHDEP,
            key,
        };
        var value: u64 = undefined;
        var len: usize = @sizeOf(@TypeOf(value));

        std.posix.sysctl(&mib, &value, &len, null, 0) catch |err| switch (err) {
            error.NameTooLong => unreachable,
            error.PermissionDenied => unreachable,
            error.SystemResources => unreachable,
            error.UnknownName => unreachable,
            error.Unexpected => return null,
        };

        return value;
    }

    fn detectNativeCpuAndFeatures(arch: std.Target.Cpu.Arch) ?std.Target.Cpu {
        const registers = [12]u64{
            0, // MIDR_EL1
            sysctlReg(std.c.CPU.AA64PFR0) orelse return null,
            sysctlReg(std.c.CPU.AA64PFR1) orelse return null,
            0, // ID_AA64DFR0_EL1
            0, // ID_AA64DFR1_EL1
            0, // ID_AA64AFR0_EL1
            0, // ID_AA64AFR1_EL1
            sysctlReg(std.c.CPU.ID_AA64ISAR0) orelse return null,
            sysctlReg(std.c.CPU.ID_AA64ISAR1) orelse return null,
            sysctlReg(std.c.CPU.ID_AA64MMFR0) orelse return null,
            sysctlReg(std.c.CPU.ID_AA64MMFR1) orelse return null,
            sysctlReg(std.c.CPU.ID_AA64MMFR2) orelse return null,
        };

        return @import("arm.zig").aarch64.detectNativeCpuAndFeatures(arch, registers);
    }
};

const powerpc = struct {
    const models = .{
        .{ "601", &std.Target.powerpc.cpu.@"601" },
        .{ "603ev", &std.Target.powerpc.cpu.@"603ev" },
        .{ "603e", &std.Target.powerpc.cpu.@"603e" },
        .{ "603", &std.Target.powerpc.cpu.@"603" },
        .{ "604ev", &std.Target.powerpc.cpu.@"604e" },
        .{ "604", &std.Target.powerpc.cpu.@"604" },
        .{ "7400", &std.Target.powerpc.cpu.@"7400" },
        .{ "7410", &std.Target.powerpc.cpu.@"7400" },
        .{ "7450", &std.Target.powerpc.cpu.@"7450" },
        .{ "7451", &std.Target.powerpc.cpu.@"7450" },
        .{ "7455", &std.Target.powerpc.cpu.@"7450" },
        .{ "7457", &std.Target.powerpc.cpu.@"7450" },
        .{ "7447A", &std.Target.powerpc.cpu.@"7450" },
        .{ "7448", &std.Target.powerpc.cpu.@"7450" },
        .{ "750FX", &std.Target.powerpc.cpu.@"750" },
        .{ "750", &std.Target.powerpc.cpu.@"750" },
        .{ "970FX", &std.Target.powerpc.cpu.@"970" },
        .{ "970MP", &std.Target.powerpc.cpu.@"970" },
        .{ "970", &std.Target.powerpc.cpu.@"970" },
        .{ "IBM POWER8E", &std.Target.powerpc.cpu.pwr8 },
        .{ "IBM POWER8NVL", &std.Target.powerpc.cpu.pwr8 },
        .{ "IBM POWER8", &std.Target.powerpc.cpu.pwr8 },
        .{ "IBM POWER9P", &std.Target.powerpc.cpu.pwr9 },
        .{ "IBM POWER9", &std.Target.powerpc.cpu.pwr9 },
    };

    fn detectNativeCpu(arch: std.Target.Cpu.Arch) ?std.Target.Cpu {
        const mib: [2]c_int = [_]c_int{
            std.c.CTL.HW,
            std.c.HW.MODEL,
        };
        var buf: [64:0]u8 = undefined;
        var len: usize = buf.len + 1;

        std.posix.sysctl(&mib, &buf, &len, null, 0) catch |err| switch (err) {
            error.NameTooLong => unreachable,
            error.PermissionDenied => unreachable,
            error.SystemResources => unreachable,
            error.UnknownName => unreachable,
            error.Unexpected => return null,
        };

        const name = buf[0 .. len - 1 :0];

        inline for (models) |pair| {
            if (std.mem.startsWith(u8, name, pair[0])) return pair[1].toCpu(arch);
        }

        return null;
    }
};

pub fn detectNativeCpuAndFeatures() ?std.Target.Cpu {
    return switch (native_arch) {
        .aarch64 => aarch64.detectNativeCpuAndFeatures(native_arch),
        .powerpc, .powerpc64 => powerpc.detectNativeCpu(native_arch),
        else => null,
    };
}
