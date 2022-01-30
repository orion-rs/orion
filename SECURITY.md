### Reporting security issues
All security issues should be reported to the author at [brycx@protonmail.com](mailto:brycx@protonmail.com).

We try to follow the [RFPolicy](https://en.wikipedia.org/wiki/RFPolicy), but with an initial response time of 2 weeks maximum. In practice, however, the initial response will most often be faster.

Please clearly indicate in the subject line, that it is about a security issue. Providing many details about the issue makes it easier and faster to fix.

Once a security issue has been confirmed and a fixed version has been released, an advisory will be submitted to the [RustSec Advisory Database](https://rustsec.org/).

Thank you for taking the time to report and improve this project!

### Threat model
The following are threats, which are considered out-of-scope for Orion.

- Any side-channel other than timing-based
- Hardware-related issues
- Leaking sensitive memory[1]
- Timing-based side-channels when not building in release mode

[1] Wiping sensitive memory is performed on a best-effort approach. However, sensitive memory being wiped or not leaked, cannot be guaranteed. See more in the [wiki](https://github.com/orion-rs/orion/wiki/Security#memory).

### Supported versions
Currently, only the latest version, released on [crates.io](https://crates.io/crates/orion), receives testing and is supported with security fixes.

There is no guarantee that a version, containing a security fix, will be SemVer-compatible to the previous one.

Backporting security fixes to older versions will be considered on an ad hoc basis.

### Yanking policy
Any version which is affected by a security issue, will be yanked. Even though we try to provide it, there is no guarantee that a SemVer-compatible version, containing a fix, will be available at the time of yanking.

### Recommended best practices
These are recommendations on how to use Orion correctly:

- Use `cargo audit` to ensure the current version has no published security vulnerabilities
- Never use `opt-level=0`, always build in release mode
- Always use the latest version of Orion