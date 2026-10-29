# Relay workspace UI — 0.117.0

For the current appearance controls and full UI review, see [0.126.0](RELEASE_0.126.0_EN.md). The original workflow below remains applicable.

This release adds English and Simplified Chinese to the console introduced in 0.116.0. The data plane, billing behavior, permissions and protocol configuration are unchanged; the broader non-payment roadmap is still in development.

## Language switch

Use **English** or **中文** in the upper-right corner of the sign-in page or the console header. The button names the language it will switch to. The interface updates in place and preserves the session, current route, node selection and theme. The browser saves the choice under `relay-language`; Chinese remains the default. If browser storage is blocked, switching still works for the current page.

The catalog covers navigation, page descriptions, tables, editors, client-side validation, notifications and all seven handbook chapters. Dates use the selected locale and retain the browser's local timezone. Search accepts both English and Chinese keywords in either interface language. User-provided names, notes, addresses, configuration values and raw backend diagnostics retain their original content. Language selection makes no configuration writes.

Messages are local, plain text with indexed interpolation; values are never treated as translated text or HTML. `web/i18n.js` manages the preference, static shell bindings and lazy label dictionaries; `web/i18n-en.js` holds the English catalog. There is no external translation service or added frontend runtime dependency.

## Design and navigation

The interface combines the grouped navigation and reading structure of [GitBook](https://gitbook.com/docs), the network-oriented presentation of [Zero Forwarder](https://www.zeroforwarder.com/), and the warm paper/ink palette and editorial typography of [inok.io](https://inok.io/). These are visual references. Their assets, branding, proprietary features and performance claims are not included in Relay.

- Twenty pages: the existing nineteen console pages plus an integrated handbook.
- Four navigation groups: workspace, observability/resources, services/collaboration, and administration/help.
- Persistent header, breadcrumbs, page descriptions and contextual help.
- Local search across page names, functional aliases and seven guide articles. Open with the search button or Command/Ctrl+K; use Up/Down and Enter to choose, Escape to close.
- Role-aware navigation/search. Restricted administration pages are omitted for tenant administrators and viewers, and restricted deep links return to the overview. API authorization remains authoritative.
- Hash links preserve the selected page on reload and support browser Back/Forward. Examples: `#rules`, `#guide/clients`. Unknown views fall back to the overview; unknown guide chapters open the quickstart.
- Warm light theme by default, with a persistent dark-theme preference.
- Responsive mobile navigation with an overlay, focus containment, Escape dismissal and a keyboard skip link. Tables and network diagrams retain local horizontal scrolling rather than widening the whole page.

## Integrated handbook

Seven articles cover node onboarding, rules/protocols/topology, observability, budgets/metering, client subscriptions, security, and operations/delivery limits. Chapters include steps, cautions, links into the corresponding console pages, next-article navigation, and a table of contents on wide screens. The page-help button opens the relevant article without leaving the current console page.

The handbook is embedded in the binary. It does not require a GitBook account, external search service, remote fonts, analytics, a CDN or an AI service. It is curated operational guidance; the detailed API and protocol references remain in the source repository's `docs/` directory.

## Implementation and operation

`web/index.html` defines the shell; `web/style.css` supplies both themes and breakpoints. `web/console-ui.js` owns the route metadata, local search, guide content and shell interactions. `web/app.js` retains the existing API clients, data renderers and forms. All six web files, including the language modules, are compiled into the Rust controller; rebuild the binary to deploy UI changes. There is no npm install/build step and no new frontend runtime dependency.

Search indexes only static page/guide content. It does not search or upload node records, credentials or configuration. The new module is served under the existing same-origin Content Security Policy. Session tokens remain in session storage; sign-out clears search results and visible console content.

The overview displays reported telemetry, with an explicit waiting state when there are no enrolled nodes or no live samples. No performance values are generated for presentation. The network diagram's nodes can be reached by keyboard and open the associated rule page.

## Scope of acceptance

The companion verification package records the actual automated and browser checks for this release. Browser acceptance uses an isolated loopback controller and three local agents with a TCP echo chain. Screenshots show this lab, not production traffic or a hardware-performance benchmark. Responsive checks emulate viewport sizes; they do not establish physical iOS/Android or cross-browser acceptance.

No test VPS was redeployed for this language-switch task. This UI update does not resolve the controller memory-limit and slow-reader findings from the 0.116.0 VPS acceptance run. New capacity and endurance claims require their own runs.
