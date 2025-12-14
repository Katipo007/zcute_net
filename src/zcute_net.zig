pub fn init(allocator: std.mem.Allocator) !void {
    const init_result = cn_init();
    try init_result.as_error();

    mem_mutex.lock();
    defer mem_mutex.unlock();

    assert(mem_allocator == null);
    mem_allocator = allocator;
    mem_allocations = std.AutoHashMap(usize, usize).init(allocator);
}

pub fn deinit() void {
    mem_mutex.lock();
    defer mem_mutex.unlock();

    assert(mem_allocator != null);
    assert(mem_allocations.?.count() == 0);

    mem_allocations.?.deinit();
    mem_allocations = null;
    mem_allocator = null;
}

pub const Error = error{
    internal_error,
    library_initialise_failed,
    out_of_memory,
    forged_message,
    empty_packets_are_not_allowed,
    client_is_not_connected,
    invalid_address,
};

pub const AddressType = switch (options.ipv6_support) {
    false => enum(c_int) { none, ipv4 },
    true => enum(c_int) { none, ipv4, ipv6 },
};

pub const Endpoint = extern struct {
    address_type: AddressType,
    port: u16,
    address: cn_endpoint_address,

    pub fn from_string(address_and_port: [*:0]const u8) error{invalid_address}!Endpoint {
        var endpoint: Endpoint = undefined;
        if (cn_endpoint_init(&endpoint, @ptrCast(address_and_port)) < 0) {
            return error.invalid_address;
        }
        return endpoint;
    }

    pub fn to_string(self: *const Endpoint, buffer: []u8) error{buffer_to_small}![]u8 {
        if (buffer.len < 46)
            return error.buffer_to_small;

        cn_endpoint_to_string(self, buffer.ptr, @intCast(buffer.len));
        return std.mem.sliceTo(buffer, 0);
    }

    pub fn to_string_alloc(self: *const Endpoint, allocator: std.mem.Allocator) ![]u8 {
        const buffer = try allocator.alloc(u8, 46);
        errdefer allocator.free(buffer);
        return to_string(self, buffer);
    }

    pub fn format(self: *const Endpoint, writer: anytype) !void {
        var buffer: [46]u8 = undefined;
        const str = to_string(self, &buffer) catch unreachable;
        try writer.print("{s}", .{str});
    }

    pub fn eql(lhs: Endpoint, rhs: Endpoint) bool {
        if (lhs.address_type != rhs.address_type)
            return false;

        if (lhs.port != rhs.port)
            return false;

        if (options.ipv6_support) {
            return switch (lhs.address_type) {
                .none => true,
                .ipv4 => std.mem.eql(u8, &lhs.address.ipv4, &rhs.address.ipv4),
                .ipv6 => std.mem.eql(u16, &lhs.address.ipv6, &rhs.address.ipv6),
            };
        } else {
            return switch (lhs.address_type) {
                .none => true,
                .ipv4 => std.mem.eql(u8, &lhs.address.ipv4, &rhs.address.ipv4),
            };
        }
        //return cn_endpoint_equals(lhs, rhs) == 0;
    }
};

pub const ConnectionToken = struct {
    pub const num_data_bytes: usize = 1114;
    pub const num_user_data_bytes: usize = 256;
    data: [num_data_bytes]u8,

    pub fn generate(
        application_id: u64,
        creation_timestamp: u64,
        client_to_server_key: *const crypto.SymmetricKey,
        server_to_client_key: *const crypto.SymmetricKey,
        expiration_timestamp: u64,
        handshake_timeout: u32,
        address_list: []const [*:0]const u8,
        client_id: u64,
        user_data: ?*const [num_user_data_bytes]u8,
        shared_secret_key: *const crypto.SecretKey,
    ) Error!ConnectionToken {
        var token = ConnectionToken{
            .data = undefined,
        };
        const result = cn_generate_connect_token(
            application_id,
            creation_timestamp,
            client_to_server_key,
            server_to_client_key,
            expiration_timestamp,
            handshake_timeout,
            @intCast(address_list.len),
            @ptrCast(address_list.ptr),
            client_id,
            if (user_data) |ptr| @ptrCast(ptr) else null,
            shared_secret_key,
            &token.data,
        );
        try result.as_error();
        return token;
    }
};

pub const ChannelType = enum {
    unreliable,
    reliable,
};

pub const Client = opaque {
    pub const Config = struct {
        application_id: u64,
        port: ?u16 = null,
        use_ipv6: bool,
    };

    pub const State = enum(c_int) {
        connection_token_expired = -6,
        invalid_connect_token = -5,
        connection_timed_out = -4,
        challenge_response_timed_out = -3,
        connection_request_timed_out = -2,
        connection_denied = -1,
        disconnected = 0,
        sending_connection_request = 1,
        sending_challenge_response = 2,
        connected = 3,
    };

    pub const Packet = struct {
        owner: *Client,
        data: []u8,
        channel_type: ChannelType,

        pub fn deinit(self: *const Packet) void {
            cn_client_free_packet(self.owner, @ptrCast(self.data.ptr));
        }
    };

    pub fn create(config: Config) Error!*Client {
        const maybe_client = cn_client_create(config.port orelse 0, config.application_id, config.use_ipv6, null);
        if (maybe_client) |client|
            return client;

        return Error.internal_error;
    }

    pub fn destroy(self: *Client) void {
        cn_client_destroy(self);
    }

    pub fn get_state(self: *const Client) State {
        return cn_client_state_get(self);
    }

    pub fn connect(self: *Client, connection_token: *const ConnectionToken) Error!void {
        const result = cn_client_connect(self, &connection_token.data);
        try result.as_error();
    }

    pub fn disconnect(self: *Client) void {
        cn_client_disconnect(self);
    }

    pub fn update(self: *Client, delta_time: f64, current_time: u64) void {
        cn_client_update(self, delta_time, current_time);
    }

    pub fn pop_packet(self: *Client) ?Packet {
        var packet_data_ptr: [*]void = undefined;
        var packet_data_size: c_int = 0;
        var was_sent_reliably: bool = false;
        if (cn_client_pop_packet(self, &packet_data_ptr, &packet_data_size, &was_sent_reliably)) {
            return Packet{
                .owner = self,
                .data = @as([*]u8, @ptrCast(packet_data_ptr))[0..@as(usize, @intCast(packet_data_size))],
                .channel_type = if (was_sent_reliably) .unreliable else .reliable,
            };
        } else {
            return null;
        }
    }

    pub const SendError = error{
        internal_error,
        empty_packets_are_not_allowed,
        client_is_not_connected,
    };
    pub fn send(self: *Client, packet: []const u8, channel: ChannelType) SendError!void {
        const result = cn_client_send(self, @ptrCast(packet.ptr), @intCast(packet.len), channel == .reliable);
        if (result.get_error()) |err| return switch (err) {
            Error.internal_error => SendError.internal_error,
            Error.client_is_not_connected => SendError.client_is_not_connected,
            Error.empty_packets_are_not_allowed => SendError.empty_packets_are_not_allowed,
            else => unreachable,
        };
    }
};

pub const Server = opaque {
    pub const Config = cn_server_config;

    pub const Event = union(enum) {
        client_connected: struct {
            client_index: c_int,
            client_id: u64,
            endpoint: Endpoint,
        },
        client_disconnected: struct {
            client_index: c_int,
        },
        packet_received: ReceivedPacket,
    };

    pub const ReceivedPacket = struct {
        owner: *Server,
        from_client_index: c_int,
        data: []u8,

        pub fn deinit(self: *const ReceivedPacket) void {
            cn_server_free_packet(self.owner, self.from_client_index, @ptrCast(self.data.ptr));
        }
    };

    pub fn create(config: Config) Error!*Server {
        const maybe_server = cn_server_create(config);
        if (maybe_server) |server|
            return server;

        return Error.internal_error;
    }

    pub fn destroy(self: *Server) void {
        cn_server_destroy(self);
    }

    pub fn start(self: *Server, address_and_port: [:0]const u8) Error!void {
        const result = cn_server_start(self, @ptrCast(address_and_port));
        try result.as_error();
    }

    pub fn stop(self: *Server) void {
        cn_server_stop(self);
    }

    pub fn pop_event(self: *Server) ?Event {
        var c_event: cn_server_event = undefined;
        if (!cn_server_pop_event(self, &c_event))
            return null;

        const event_type = c_event.type;
        const event_data = &c_event.data;
        switch (event_type) {
            .new_connection => {
                return Event{
                    .client_connected = .{
                        .client_index = event_data.new_connection.client_index,
                        .client_id = event_data.new_connection.client_id,
                        .endpoint = event_data.new_connection.endpoint,
                    },
                };
            },
            .disconnected => {
                return Event{
                    .client_disconnected = .{
                        .client_index = event_data.disconnected.client_index,
                    },
                };
            },
            .payload_packet => {
                const payload_ptr: [*]u8 = @ptrCast(event_data.payload_packet.data);
                const payload_len: usize = @intCast(event_data.payload_packet.data_size);
                return Event{
                    .packet_received = .{
                        .owner = self,
                        .from_client_index = event_data.payload_packet.client_index,
                        .data = payload_ptr[0..payload_len],
                    },
                };
            },
        }
    }

    pub fn update(self: *Server, delta_time: f64, current_time: u64) void {
        cn_server_update(self, delta_time, current_time);
    }

    pub fn disconnect_client(self: *Server, client_index: c_int, notify_client: bool) void {
        cn_server_disconnect_client(self, client_index, notify_client);
    }

    pub fn send(self: *Server, client_index: c_int, channel: ChannelType, packet: []const u8) !void {
        const result = cn_server_send(self, @ptrCast(packet.ptr), @intCast(packet.len), client_index, channel == .reliable);
        try result.as_error();
    }

    pub fn is_client_connected(self: *const Server, client_index: c_int) bool {
        return cn_server_is_client_connected(@constCast(self), client_index);
    }
};

pub const crypto = struct {
    pub fn random_bytes(data: []u8) void {
        cn_crypto_random_bytes(data.ptr, @intCast(data.len));
    }

    pub const Signature = extern struct {
        pub const num_data_bytes: usize = 64;
        bytes: [num_data_bytes]u8,
    };

    pub const SymmetricKey = extern struct {
        pub const num_data_bytes: usize = 32;
        key: [num_data_bytes]u8,

        pub fn generate() SymmetricKey {
            return cn_crypto_generate_key();
        }

        pub fn encrypt(self: *const SymmetricKey, data: []u8, msg_id: u64) void {
            cn_crypto_encrypt(self, data.ptr, @intCast(data.len), msg_id);
        }

        pub const DecryptError = error{
            forged_message,
        };
        pub fn decrypt(self: *const SymmetricKey, data: []u8, msg_id: u64) DecryptError!void {
            const result = cn_crypto_decrypt(self, data.ptr, @intCast(data.len), msg_id);
            if (result.is_error())
                return DecryptError.forged_message;
        }
    };

    pub const PublicKey = extern struct {
        pub const num_data_bytes: usize = 32;
        key: [num_data_bytes]u8,

        pub const VerifyError = error{
            forged_message,
        };
        pub fn verify(self: *const PublicKey, signature: *const Signature, data: []const u8) VerifyError!void {
            const result = cn_crypto_sign_verify(self, signature, data.ptr, @intCast(data.len));
            if (result.is_error())
                return VerifyError.forged_message;
        }
    };

    pub const SecretKey = extern struct {
        pub const num_data_bytes: usize = 64;
        key: [num_data_bytes]u8,

        pub fn sign(self: *const SecretKey, data: []const u8) Signature {
            var result: Signature = undefined;
            cn_crypto_sign_create(self, &result, data.ptr, @intCast(data.len));
            return result;
        }
    };

    pub const AsymmetricKey = struct {
        public_key: PublicKey,
        secret_key: SecretKey,

        pub fn generate() AsymmetricKey {
            var result: AsymmetricKey = undefined;
            cn_crypto_sign_keygen(&result.public_key, &result.secret_key);
            return result;
        }
    };
};

comptime {
    // Require the exported functions to be present in the resulting binary.
    _ = exports;
}

//
// internals
//

var mem_allocator: ?std.mem.Allocator = null;
var mem_allocations: ?std.AutoHashMap(usize, usize) = null;
var mem_mutex: std.Thread.Mutex = .{};
const mem_alignment = @alignOf(std.c.max_align_t);
const assert = exports.zcute_net_assert;

const exports = struct {
    export fn zcute_net_allocate(size: usize, _: ?*anyopaque) callconv(.c) ?*anyopaque {
        mem_mutex.lock();
        defer mem_mutex.unlock();

        const mem = mem_allocator.?.alignedAlloc(
            u8,
            .fromByteUnits(mem_alignment),
            size,
        ) catch @panic("zcute_net: out of memory");

        mem_allocations.?.put(@intFromPtr(mem.ptr), size) catch @panic("zcute_net: out of memory");

        return mem.ptr;
    }
    export fn zcute_net_free(maybe_ptr: [*c]u8, _: ?*anyopaque) callconv(.c) void {
        const ptr = maybe_ptr orelse return;

        mem_mutex.lock();
        defer mem_mutex.unlock();

        const size = mem_allocations.?.fetchRemove(@intFromPtr(ptr)).?.value;
        const mem = @as([*]align(mem_alignment) u8, @ptrCast(@alignCast(ptr)))[0..size];
        mem_allocator.?.free(mem);
    }
    export fn zcute_net_assert(cond: bool) callconv(.c) void {
        std.debug.assert(cond);
    }
    export fn zcute_net_memcpy(dest: *anyopaque, src: *const anyopaque, count: usize) callconv(.c) *anyopaque {
        @memcpy(@as([*c]u8, @ptrCast(dest))[0..count], @as([*c]const u8, @ptrCast(src))[0..count]);
        return dest;
    }
    export fn zcute_net_memset(dest: *anyopaque, ch: c_int, count: usize) callconv(.c) *anyopaque {
        @memset(@as([*c]u8, @ptrCast(dest))[0..count], @as(u8, @truncate(@as(c_uint, @bitCast(ch)))));
        return dest;
    }
    export fn zcute_net_memcmp(lhs: *const anyopaque, rhs: *const anyopaque, count: usize) callconv(.c) c_int {
        return switch (std.mem.order(u8, @as([*c]const u8, @ptrCast(lhs))[0..count], @as([*c]const u8, @ptrCast(rhs))[0..count])) {
            .eq => 0,
            .lt => -1,
            .gt => 1,
        };
    }
};

const cn_result = extern struct {
    code: enum(c_int) {
        success = 0,
        failure = -1,
    },
    details: [*c]const u8,

    fn is_error(result: cn_result) bool {
        return result.code != .success;
    }

    fn get_error(result: cn_result) ?Error {
        if (!is_error(result))
            return null;

        const details = if (result.details) |details_cstr| std.mem.sliceTo(details_cstr, 0) else return Error.internal_error;
        if (std.mem.startsWith(u8, details, "Unable to initialize endpoint"))
            return Error.invalid_address;
        if (std.mem.startsWith(u8, details, "Unable to initializ"))
            return Error.library_initialise_failed;
        if (std.mem.startsWith(u8, details, "Empty packets are no"))
            return Error.empty_packets_are_not_allowed;
        if (std.mem.startsWith(u8, details, "Client is not connected"))
            return Error.client_is_not_connected;
        if (std.mem.startsWith(u8, details, "Message forged"))
            return Error.forged_message;

        log.err("cute_net error encountered: '{s}'", .{result.details});
        return Error.internal_error;
    }

    fn as_error(result: cn_result) Error!void {
        if (get_error(result)) |err| {
            return err;
        }
    }
};
extern fn cn_init() cn_result;

extern fn cn_endpoint_init(endpoint: *Endpoint, address_and_port_string: [*:0]const c_char) c_int;
extern fn cn_endpoint_to_string(endpoint: *const Endpoint, buffer: [*]u8, buffer_size: c_int) void;
extern fn cn_endpoint_equals(a: Endpoint, b: Endpoint) c_int;
const cn_endpoint_address = switch (options.ipv6_support) {
    false => extern union { ipv4: [4]u8 },
    true => extern union { ipv4: [4]u8, ipv6: [8]u16 },
};

extern fn cn_generate_connect_token(
    application_id: u64,
    creation_timestamp: u64,
    client_to_server_key: *const crypto.SymmetricKey,
    server_to_client_key: *const crypto.SymmetricKey,
    expiration_timestamp: u64,
    handshake_timeout: u32,
    address_count: c_int,
    address_list: [*]const c_char,
    client_id: u64,
    user_data: ?[*]const u8,
    shared_secret_key: *const crypto.SecretKey,
    token_ptr_out: [*]u8,
) cn_result;

extern fn cn_client_create(port: u16, application_id: u64, use_ipv6: bool, user_allocator_context: ?*anyopaque) ?*Client;
extern fn cn_client_destroy(client: *Client) void;
extern fn cn_client_connect(client: *Client, connection_token: *const [ConnectionToken.num_data_bytes]u8) cn_result;
extern fn cn_client_disconnect(client: *Client) void;
extern fn cn_client_update(client: *Client, delta_time: f64, current_time: u64) void;
extern fn cn_client_pop_packet(client: *Client, packet: *[*]void, size: *c_int, was_sent_reliably: *bool) bool;
extern fn cn_client_free_packet(client: *Client, packet: [*]void) void;
extern fn cn_client_send(client: *Client, packet: [*]const void, packet_size: c_int, send_reliably: bool) cn_result;
extern fn cn_client_state_get(client: *const Client) Client.State;

const cn_server_config = extern struct {
    application_id: u64,
    max_incoming_bytes_per_second: c_int = 0,
    max_outgoing_bytes_per_second: c_int = 0,
    connection_timeout: c_int = 10,
    resend_rate: f64 = 0.1,
    public_key: crypto.PublicKey,
    secret_key: crypto.SecretKey,
    user_allocator_context: ?*anyopaque = null,
};
extern fn cn_server_create(config: cn_server_config) ?*Server;
extern fn cn_server_destroy(server: *Server) void;
extern fn cn_server_start(server: *Server, address_and_port: [*:0]const c_char) cn_result;
extern fn cn_server_stop(server: *Server) void;
extern fn cn_server_pop_event(server: *Server, event: *cn_server_event) bool;
extern fn cn_server_free_packet(server: *Server, client_index: c_int, data: [*]void) void;
extern fn cn_server_update(server: *Server, delta_time: f64, current_time: u64) void;
extern fn cn_server_disconnect_client(server: *Server, client_index: c_int, notify_client: bool) void;
extern fn cn_server_send(server: *Server, packet: *const void, packet_size: c_int, client_index: c_int, send_reliably: bool) cn_result;
extern fn cn_server_is_client_connected(server: *Server, client_index: c_int) bool;
const cn_server_event_type = enum(c_int) {
    new_connection,
    disconnected,
    payload_packet,
};
const cn_server_event = extern struct {
    type: cn_server_event_type,
    data: extern union {
        new_connection: extern struct {
            client_index: c_int,
            client_id: u64,
            endpoint: Endpoint,
        },

        disconnected: extern struct {
            client_index: c_int,
        },

        payload_packet: extern struct {
            client_index: c_int,
            data: [*]void,
            data_size: c_int,
        },
    },
};

extern fn cn_crypto_random_bytes(data: [*]u8, byte_count: c_int) void;
extern fn cn_crypto_generate_key() crypto.SymmetricKey;
extern fn cn_crypto_encrypt(key: *const crypto.SymmetricKey, data: [*]u8, data_size: c_int, msg_id: u64) void;
extern fn cn_crypto_decrypt(key: *const crypto.SymmetricKey, data: [*]u8, data_size: c_int, msg_id: u64) cn_result;
extern fn cn_crypto_sign_verify(self: *const crypto.PublicKey, signature: *const crypto.Signature, data: [*]const u8, data_size: c_int) cn_result;
extern fn cn_crypto_sign_create(secret_key: *const crypto.SecretKey, signature: *crypto.Signature, data: [*]const u8, data_size: c_int) void;
extern fn cn_crypto_sign_keygen(public_key: *crypto.PublicKey, private_key: *crypto.SecretKey) void;
//extern fn cn_run_tests(test_index: c_int, soak: bool) callconv(.c) c_int;

//
// imports + internal constants
//

const std = @import("std");
const builtin = @import("builtin");
const options = @import("options");
const log = std.log.scoped(.zcute_net);

//
// tests
//

test "Compile" {
    std.testing.refAllDecls(@This());
    std.testing.refAllDeclsRecursive(Server);
    std.testing.refAllDeclsRecursive(Client);
    std.testing.refAllDeclsRecursive(Endpoint);
    std.testing.refAllDeclsRecursive(crypto);
}

// test "C Unit Tests" {
//     try std.testing.expectEqual(@as(c_int, 0), cn_run_tests(-1, false));
// }

test "Basic Usage" {
    const allocator = std.testing.allocator;
    try init(allocator);
    defer deinit();

    const server_key = crypto.AsymmetricKey.generate();
    const server = try Server.create(.{
        .application_id = 0,
        .public_key = server_key.public_key,
        .secret_key = server_key.secret_key,
    });
    defer server.destroy();

    const host_address = "127.0.0.1:5004";
    try server.start(host_address);
    defer server.stop();

    const connection_token = try ConnectionToken.generate(
        0,
        @intCast(std.time.timestamp()),
        &crypto.SymmetricKey.generate(),
        &crypto.SymmetricKey.generate(),
        @intCast(std.time.timestamp() + 10),
        10,
        &.{
            host_address,
        },
        1,
        null,
        &server_key.secret_key,
    );

    const client = try Client.create(.{
        .application_id = 0,
        .port = null,
        .use_ipv6 = false,
    });
    defer client.destroy();

    try client.connect(&connection_token);
    defer client.disconnect();

    var stats: struct {
        num_client_connects: usize = 0,
        num_packets_sent: usize = 0,
        num_packets_received: usize = 0,
        num_hello_worlds_received: usize = 0,
    } = .{};

    const num_packets_per_second = 2000;
    const send_packet_cooldown_duration: f64 = 1.0 / @as(f64, @floatFromInt(num_packets_per_second));
    var send_packet_cooldown_time: f64 = 0;

    const dt = 0.1;
    var total_time: f64 = 0;
    var simulation_time: f64 = 0;
    var time_accumulator: f64 = 0;
    var timer = try std.time.Timer.start();
    while (total_time <= 5.0) {
        var frame_time = @as(f64, @floatFromInt(timer.lap())) / @as(comptime_float, @floatFromInt(std.time.ns_per_s));
        if (frame_time > 0.25)
            frame_time = 0.25;

        time_accumulator += frame_time;
        total_time += frame_time;

        while (time_accumulator >= dt) {
            simulation_time += dt;
            time_accumulator -= dt;

            server.update(dt, @intCast(std.time.timestamp()));
            while (server.pop_event()) |event| switch (event) {
                .client_connected => |e| {
                    std.log.debug("Client {d} connected {f}", .{ e.client_index, e.endpoint });
                    stats.num_client_connects += 1;
                },
                .client_disconnected => |e| {
                    std.log.debug("Client {d} disconnected", .{e.client_index});
                },
                .packet_received => |p| {
                    defer p.deinit();

                    stats.num_packets_received += 1;

                    if (std.mem.eql(u8, p.data, "Hello, world!"))
                        stats.num_hello_worlds_received += 1;
                },
            };

            client.update(dt, @intCast(std.time.timestamp()));
            while (client.pop_packet()) |packet| {
                defer packet.deinit();
            }

            switch (client.get_state()) {
                .connected => {
                    send_packet_cooldown_time -= dt;
                    if (send_packet_cooldown_time > 0)
                        break;

                    try client.send("Hello, world!", .reliable);
                    send_packet_cooldown_time = send_packet_cooldown_duration;
                    stats.num_packets_sent += 1;
                },
                else => {},
            }
        }
    }

    try std.testing.expectEqual(1, stats.num_client_connects);
    try std.testing.expect(stats.num_packets_sent > 0);
    try std.testing.expect(stats.num_packets_received > 0);
    try std.testing.expect(stats.num_hello_worlds_received > 0);
}

test "Generate connection token" {
    const client_to_server_key = crypto.SymmetricKey.generate();
    const server_to_client_key = crypto.SymmetricKey.generate();
    const login_server_key = crypto.AsymmetricKey.generate();

    const endpoints: [3][*:0]const u8 = .{
        "127.0.0.1:5000",
        "127.0.0.1:5001",
        "127.0.0.1:5002",
    };

    const now: u64 = @intCast(std.time.timestamp());
    const connection_token = try ConnectionToken.generate(
        1234,
        now,
        &client_to_server_key,
        &server_to_client_key,
        now + 10,
        10,
        &endpoints,
        17,
        null,
        &login_server_key.secret_key,
    );
    _ = connection_token;
}

test "Endpoint from string" {
    try std.testing.expectEqual(AddressType.ipv4, (try Endpoint.from_string("127.0.0.1:5000")).address_type);
    if (options.ipv6_support)
        try std.testing.expectEqual(AddressType.ipv6, (try Endpoint.from_string("[::]:5000")).address_type);
}
