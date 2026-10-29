# Relay Platform 0.116.0 — UI delivery summary

Version 0.116.0 gives the existing Relay console a consistent workspace and an integrated handbook. It follows the navigation and reading structure of [GitBook](https://gitbook.com/docs), the network-oriented presentation of [Zero Forwarder](https://www.zeroforwarder.com/), and the warm paper palette and typography of [inok.io](https://inok.io/). The implementation is in the supplied source; it has no dependency on these services.

## Delivered

- Twenty views organized into four navigation groups, with breadcrumbs, page descriptions and contextual help.
- Search across pages, aliases and seven embedded guide articles. Command/Ctrl+K, arrow keys, Enter and Escape work, and results respect the current role.
- Shareable page/chapter links, reload persistence, and browser Back/Forward navigation.
- Light and dark themes, responsive mobile navigation, focus handling, touch-friendly forms and a keyboard skip link.
- A handbook covering onboarding, rules/protocols, monitoring, quotas, subscriptions, security and operations, including related-page links and a wide-screen table of contents.
- Clear waiting states for an empty or unreported fleet, and a working retry action after a failed page load.
- Existing rule editors and management workflows retained. A rule change was published through the redesigned UI and applied by a local Agent.

All four UI files are embedded in the Rust controller and served from the same origin under its Content Security Policy. No frontend framework, npm build step, remote font, CDN, analytics or external search service was added. The raw HTML/CSS/JavaScript total is 305,907 bytes; this is an asset-size measurement, not a runtime-memory or server-capacity claim.

## Verification

The default `sh scripts/verify.sh` pipeline completed successfully on macOS ARM64:

| Check | Result |
| --- | --- |
| Rust formatting and Clippy with warnings denied | Passed |
| Default Rust tests | 451 passed, 0 failed |
| Deployment Python tests | 30 passed |
| JavaScript regression scripts | 7 passed |
| Optimized controller build | Passed |
| Release HTTP asset/MIME/CSP checks | All 4 UI files match the source exactly |

Six Rust tests are marked ignored in the default output: one subprocess helper is exercised indirectly, and five optional engine/client integration tests were not selected. These five tests, Linux/WAN acceptance and endurance tests were not rerun for this UI release.

The local toolchain emitted one non-fatal release-build warning: `rust-objcopy` could not load `libLLVM.dylib` to strip debug information. Cargo completed successfully. The resulting controller passed the direct HTTP checks and browser smoke test.

Browser acceptance covered all twenty pages at desktop and phone widths, tablet and wide-screen layouts, three roles, search and keyboard navigation, deep links, history, themes, mobile dialogs, sign-out and a forced API failure followed by retry. The rule editor published revision 2 and the local Agent reported revision 2 applied. A fresh release controller also passed sign-in, empty-state and guide/search checks. Final preview and release browser logs contained no warnings or errors.

Screenshots show an isolated loopback lab with three real local Agents and generated TCP echo traffic. They are not production traffic or performance benchmarks. Viewport emulation does not establish physical-device or cross-browser acceptance. Twenty selected palette contrast pairs exceed 4.5:1; this is a token calculation, not a full accessibility certification.

## Source and deployment

The source ZIP contains the complete tracked project, including the existing optional protocol-engine source archive and licenses. The verification ZIP contains the automated log, structured results, asset checks and screenshots. It excludes test state, credentials and databases.

To rebuild the embedded UI, run `cargo build --locked --release` using the repository's supported Rust toolchain. Follow the existing deployment documentation for installing the resulting binary. Editing the separate `web/` files does not update a previously built controller.

No VPS was redeployed for this task. This release completes the UI redesign described above; the broader non-payment roadmap continues to be tracked in [NONPAYMENT_DELIVERY.md](NONPAYMENT_DELIVERY.md). Payment development remains outside this task.

See [UI_WORKSPACE_EN.md](UI_WORKSPACE_EN.md) for the interface and implementation guide.
