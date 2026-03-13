// services.zig — Well-known port to service name mappings
// This is basically /etc/services but hardcoded because
// we can't rely on that file being present on every system.
// Yes, this is a giant switch statement. No, I'm not sorry.

// services.zig — Well-known port to service name mappings
const std = @import("std");

pub fn lookupPort(port: u16) []const u8 {
    return switch (port) {
        // The classics
        7   => "echo",
        9   => "discard",
        13  => "daytime",
        20  => "ftp-data",
        21  => "ftp",
        22  => "ssh",
        23  => "telnet",
        25  => "smtp", // Bir kez burada tanımlı
        37  => "time",
        43  => "whois",
        53  => "dns",
        67  => "dhcp-server",
        68  => "dhcp-client",
        69  => "tftp",
        70  => "gopher",
        79  => "finger",
        80  => "http",
        88  => "kerberos",
        102 => "iso-tsap",
        110 => "pop3",
        111 => "rpcbind",
        119 => "nntp",
        123 => "ntp",
        135 => "msrpc",
        137 => "netbios-ns",
        138 => "netbios-dgm",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        162 => "snmp-trap",
        177 => "xdmcp",
        179 => "bgp",
        194 => "irc",
        389 => "ldap",
        443 => "https",
        445 => "smb",
        465 => "smtps",
        500 => "isakmp",
        514 => "syslog",
        515 => "printer",
        520 => "rip",
        587 => "smtp-submission",
        631 => "ipp",
        636 => "ldaps",
        993 => "imaps",
        995 => "pop3s",

        // Database ports
        1433 => "mssql",
        1521 => "oracle",
        3306 => "mysql",
        5432 => "postgresql",
        5984 => "couchdb",
        6379 => "redis",
        9200 => "elasticsearch",
        27017 => "mongodb",

        // Remote access
        3389 => "rdp",
        5900 => "vnc",
        5901 => "vnc-1",
        5902 => "vnc-2",

        // Web proxies and alt-HTTP
        3128 => "squid-proxy",
        8000 => "http-alt",
        8008 => "http-alt",
        8080 => "http-proxy",
        8443 => "https-alt",
        8888 => "http-alt",
        
        // Infrastructure & Dev
        2375 => "docker",
        2376 => "docker-tls",
        2379 => "etcd",
        2380 => "etcd-peer",
        4369 => "epmd",
        5000 => "upnp/flask",
        5672 => "amqp",
        6443 => "kubernetes",
        9092 => "kafka",
        9093 => "kafka-ssl",
        15672 => "rabbitmq-mgmt",

        // Game and misc
        25565 => "minecraft",
        19132 => "minecraft-bedrock",
        27015 => "steam",
        27016 => "steam",

        // VPN
        1194 => "openvpn",
        1723 => "pptp",
        4500 => "ipsec-nat",
        51820 => "wireguard",

        // Monitoring
        9090 => "prometheus", // Artık sadece burada tanımlı
        9100 => "node-exporter",
        3000 => "grafana",

        // Catch-all
        else => "unknown",
    };
}

pub const TOP_100_PORTS = [_]u16{
    21, 22, 23, 25, 53, 67, 68, 69, 80, 88,
    110, 111, 123, 135, 137, 138, 139, 143, 161, 179,
    389, 443, 445, 465, 500, 514, 515, 587, 631, 636,
    993, 995, 1194, 1433, 1521, 1723, 2375, 2376, 2379, 2380,
    3000, 3128, 3306, 3389, 4369, 4500, 5432, 5672, 5900, 5984,
    6379, 6443, 8000, 8008, 8080, 8443, 8888, 9090, 9092, 9100,
    9200, 15672, 19132, 25565, 27015, 27017, 51820,
    4444, 4445, 5555, 6666, 7777, 9999,
};

pub fn isSensitivePort(port: u16) bool {
    return switch (port) {
        21, 23, 2375, 6379, 9200, 27017, 3389, 5900, 3306, 5432, 1433, 9090, 2379 => true,
        else => false,
    };
}
