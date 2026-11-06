use libc::c_int;

use super::{MessageType, RoutingStack, WireFormat};

// The routing socket constants from net/route.h. libc only exposes them on
// macOS, the iOS SDK does not ship net/route.h, but the kernel interface is
// the same on all Darwin targets.
// https://github.com/rust-lang/libc/pull/5158

pub const RTF_GATEWAY: c_int = 0x2;
pub const RTF_IFSCOPE: c_int = 0x1000000;

pub const RTA_DST: c_int = 0x1;
pub const RTA_GATEWAY: c_int = 0x2;
pub const RTA_NETMASK: c_int = 0x4;
pub const RTA_IFP: c_int = 0x10;
pub const RTA_IFA: c_int = 0x20;
pub const RTA_BRD: c_int = 0x80;

pub const RTAX_DST: c_int = 0;
pub const RTAX_GATEWAY: c_int = 1;
pub const RTAX_NETMASK: c_int = 2;
pub const RTAX_IFP: c_int = 4;
pub const RTAX_BRD: c_int = 7;
pub const RTAX_MAX: c_int = 8;

pub const RTM_VERSION: c_int = 5;

// Message types
pub const RTM_ADD: c_int = 0x1;
pub const RTM_DELETE: c_int = 0x2;
pub const RTM_CHANGE: c_int = 0x3;
pub const RTM_GET: c_int = 0x4;
pub const RTM_LOSING: c_int = 0x5;
pub const RTM_REDIRECT: c_int = 0x6;
pub const RTM_MISS: c_int = 0x7;
pub const RTM_LOCK: c_int = 0x8;
pub const RTM_RESOLVE: c_int = 0xb;
pub const RTM_NEWADDR: c_int = 0xc;
pub const RTM_DELADDR: c_int = 0xd;
pub const RTM_IFINFO: c_int = 0xe;
pub const RTM_NEWMADDR: c_int = 0xf;
pub const RTM_DELMADDR: c_int = 0x10;
pub const RTM_IFINFO2: c_int = 0x12;
pub const RTM_NEWMADDR2: c_int = 0x13;
pub const RTM_GET2: c_int = 0x14;

// Hardcoded based on the generated values here: https://cs.opensource.google/go/x/net/+/master:route/zsys_darwin.go
const SIZEOF_IF_MSGHDR_DARWIN15: usize = 0x70;
const SIZEOF_IFA_MSGHDR_DARWIN15: usize = 0x14;
const SIZEOF_IFMA_MSGHDR_DARWIN15: usize = 0x10;
const SIZEOF_IF_MSGHDR2_DARWIN15: usize = 0xa0;
const SIZEOF_IFMA_MSGHDR2_DARWIN15: usize = 0x14;
const SIZEOF_IF_DATA_DARWIN15: usize = 0x60;
const SIZEOF_IF_DATA64_DARWIN15: usize = 0x80;

const SIZEOF_RT_MSGHDR_DARWIN15: usize = 0x5c;
const SIZEOF_RT_MSGHDR2_DARWIN15: usize = 0x5c;
const SIZEOF_RT_METRICS_DARWIN15: usize = 0x38;

const SIZEOF_SOCKADDR_STORAGE: usize = 0x80;
pub(super) const SIZEOF_SOCKADDR_INET: usize = 0x10;
pub(super) const SIZEOF_SOCKADDR_INET6: usize = 0x1c;

pub(super) fn probe_routing_stack() -> RoutingStack {
    let rtm_version = RTM_VERSION;

    let rtm = WireFormat {
        ext_off: 36,
        body_off: SIZEOF_RT_MSGHDR_DARWIN15,
        typ: MessageType::Route,
    };
    let rtm2 = WireFormat {
        ext_off: 36,
        body_off: SIZEOF_RT_MSGHDR2_DARWIN15,
        typ: MessageType::Route,
    };
    let ifm = WireFormat {
        ext_off: 16,
        body_off: SIZEOF_IF_MSGHDR_DARWIN15,
        typ: MessageType::Interface,
    };
    let ifm2 = WireFormat {
        ext_off: 32,
        body_off: SIZEOF_IF_MSGHDR2_DARWIN15,
        typ: MessageType::Interface,
    };
    let ifam = WireFormat {
        ext_off: SIZEOF_IFA_MSGHDR_DARWIN15,
        body_off: SIZEOF_IFA_MSGHDR_DARWIN15,
        typ: MessageType::InterfaceAddr,
    };
    let ifmam = WireFormat {
        ext_off: SIZEOF_IFMA_MSGHDR_DARWIN15,
        body_off: SIZEOF_IFMA_MSGHDR_DARWIN15,
        typ: MessageType::InterfaceMulticastAddr,
    };
    let ifmam2 = WireFormat {
        ext_off: SIZEOF_IFMA_MSGHDR2_DARWIN15,
        body_off: SIZEOF_IFMA_MSGHDR2_DARWIN15,
        typ: MessageType::InterfaceMulticastAddr,
    };

    let wire_formats = [
        (RTM_ADD, rtm),
        (RTM_DELETE, rtm),
        (RTM_CHANGE, rtm),
        (RTM_GET, rtm),
        (RTM_LOSING, rtm),
        (RTM_REDIRECT, rtm),
        (RTM_MISS, rtm),
        (RTM_LOCK, rtm),
        (RTM_RESOLVE, rtm),
        (RTM_NEWADDR, ifam),
        (RTM_DELADDR, ifam),
        (RTM_IFINFO, ifm),
        (RTM_NEWMADDR, ifmam),
        (RTM_DELMADDR, ifmam),
        (RTM_IFINFO2, ifm2),
        (RTM_NEWMADDR2, ifmam2),
        (RTM_GET2, rtm2),
    ]
    .into_iter()
    .collect();

    RoutingStack {
        rtm_version,
        wire_formats,
        kernel_align: 4,
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    /// The constants above are defined locally because libc does not expose
    /// them on iOS. Make sure they agree with libc where it does.
    #[test]
    fn constants_match_libc() {
        let pairs = [
            ("RTF_GATEWAY", RTF_GATEWAY, libc::RTF_GATEWAY),
            ("RTF_IFSCOPE", RTF_IFSCOPE, libc::RTF_IFSCOPE),
            ("RTA_DST", RTA_DST, libc::RTA_DST),
            ("RTA_GATEWAY", RTA_GATEWAY, libc::RTA_GATEWAY),
            ("RTA_NETMASK", RTA_NETMASK, libc::RTA_NETMASK),
            ("RTA_IFP", RTA_IFP, libc::RTA_IFP),
            ("RTA_IFA", RTA_IFA, libc::RTA_IFA),
            ("RTA_BRD", RTA_BRD, libc::RTA_BRD),
            ("RTAX_DST", RTAX_DST, libc::RTAX_DST),
            ("RTAX_GATEWAY", RTAX_GATEWAY, libc::RTAX_GATEWAY),
            ("RTAX_NETMASK", RTAX_NETMASK, libc::RTAX_NETMASK),
            ("RTAX_IFP", RTAX_IFP, libc::RTAX_IFP),
            ("RTAX_BRD", RTAX_BRD, libc::RTAX_BRD),
            ("RTAX_MAX", RTAX_MAX, libc::RTAX_MAX),
            ("RTM_VERSION", RTM_VERSION, libc::RTM_VERSION),
            ("RTM_ADD", RTM_ADD, libc::RTM_ADD),
            ("RTM_DELETE", RTM_DELETE, libc::RTM_DELETE),
            ("RTM_CHANGE", RTM_CHANGE, libc::RTM_CHANGE),
            ("RTM_GET", RTM_GET, libc::RTM_GET),
            ("RTM_LOSING", RTM_LOSING, libc::RTM_LOSING),
            ("RTM_REDIRECT", RTM_REDIRECT, libc::RTM_REDIRECT),
            ("RTM_MISS", RTM_MISS, libc::RTM_MISS),
            ("RTM_LOCK", RTM_LOCK, libc::RTM_LOCK),
            ("RTM_RESOLVE", RTM_RESOLVE, libc::RTM_RESOLVE),
            ("RTM_NEWADDR", RTM_NEWADDR, libc::RTM_NEWADDR),
            ("RTM_DELADDR", RTM_DELADDR, libc::RTM_DELADDR),
            ("RTM_IFINFO", RTM_IFINFO, libc::RTM_IFINFO),
            ("RTM_NEWMADDR", RTM_NEWMADDR, libc::RTM_NEWMADDR),
            ("RTM_DELMADDR", RTM_DELMADDR, libc::RTM_DELMADDR),
            ("RTM_IFINFO2", RTM_IFINFO2, libc::RTM_IFINFO2),
            ("RTM_NEWMADDR2", RTM_NEWMADDR2, libc::RTM_NEWMADDR2),
            ("RTM_GET2", RTM_GET2, libc::RTM_GET2),
        ];
        for (name, ours, libc) in pairs {
            assert_eq!(ours, libc, "{name}");
        }
    }
}
