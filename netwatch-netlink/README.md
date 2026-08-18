# netwatch-netlink

Minimal rtnetlink client used by [netwatch](https://crates.io/crates/netwatch)
on Linux and Android.

It covers exactly the subset of the netlink route protocol that netwatch
needs: dumping links, addresses and routes, looking up a link by index, and
listening to rtnetlink multicast groups for change events. It is not a
general-purpose netlink library; if you need one, use the
[rust-netlink](https://github.com/rust-netlink) crates instead.

On every platform other than Linux and Android the crate compiles to
nothing.

# License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](../LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](../LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.
