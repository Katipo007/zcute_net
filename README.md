# [zcute_net](https://github.com/Katipo007/zcute_net)

[Zig](https://ziglang.org/) bindings and build package for [cute_net.h](https://github.com/RandyGaul/cute_headers/blob/master/cute_net.h) from [Randy Gaul's cute_headers](https://github.com/RandyGaul/cute_headers).

## Getting started

Add `zcute_net` to your `build.zig.zon` .dependencies with:

```
zig fetch --save git+https://github.com/Katipo007/zcute_net
```

and in your `build.zig` add:

```zig
pub fn build(b: *std.Build) void {
    const dep_zcute_net = b.dependency("zcute_net", .{});
    
    const exe = b.addExecutable(.{ ... });
    exe.root_module.addImport("zcute_net", dep_zcute_net.module("zcute_net"));
}
```
Now in your code you may import and use `zcute_net`.
