# Rconntrack

Rconntrack is conntrack command in Rust.

Conntrack command is the userspace tool for inspecting Linux connection tracking subsystem and it is a part of [conntrack-tools](https://conntrack-tools.netfilter.org/).

conntrack-tools has two components; `conntrackd` and `conntrack`.

Rconntrack provides equivalent features to `conntrack`.

## Features

Currently, rconntrack is under development and only supports limited features.

- [x] list
- [x] get
- [ ] delete
- [ ] create
- [ ] update
- [x] event
- [ ] flush
- [ ] show counter
- [ ] show statistics

## License

Rconntrack is licensed under the MIT License. See [LICENCE](./LICENSE) for the full license text.
