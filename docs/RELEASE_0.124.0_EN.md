# Edit forwarding paths from the diagram — 0.124.0

The VPS cards in the guided setup diagram are now buttons. Selecting a card highlights that hop and opens its settings directly beneath the diagram. The editor reuses the original form controls, so changing the diagram and changing the VPS picker cannot create separate drafts.

## Try it

1. Open **Forwarding paths → Create forwarding path**, or choose a built-in template.
2. Choose entry, optional relay and exit VPSs. Existing address defaults and automatic port allocation still apply.
3. Click an **entry, relay or exit card** in the diagram. Keyboard users can Tab to a card and press Enter or Space.
4. In the editor below the diagram, change the VPS, enable manual addresses/ports, or set that hop's allowed source CIDRs. Relay controls allow reordering or removal. Selecting the exit also brings its fixed destination or Shadowsocks settings into this editor. SS remains on the final hop.
5. Click **Done editing this hop** to keep the draft and return focus to its card, or select another card to continue editing.
6. Click **Preview changes**. If you spot something to change, click its card in the validated diagram. You return to that hop's draft editor and must preview again before publication. The earlier validated batch is not modified in place.
7. Click **Publish these changes** only after reviewing the revised path. Confirm Agent application and test real traffic separately.

On the **published path page**, clicking a VPS card fetches current node/configuration data and opens that exact node rule. Existing revision checks and stop-before-reroute protections remain in effect. Read-only users receive a noninteractive diagram. Client, external-destination and unresolved-reference cards do not offer a misleading edit action.

The advanced single-rule editor still uses its existing form controls and a live diagram. Its validated review lets you return to that rule; downstream rules are edited separately from the published path page.

## Verification and scope

The source includes executable checks for card selection, original-control reuse, selected VPS changes, relay removal, manual endpoint edits, focus and horizontal-scroll preservation, fresh saved-rule dispatch, read-only behavior, and review-to-edit isolation. The verification package records bilingual UI tests and browser acceptance of editing, re-previewing, publishing, and reopening the correct saved hop.

This is a controller UI update. No forwarding-engine, Agent rule-format or state-schema changes are introduced. Local panels must run the rebuilt controller and reload their browser assets. This release does not establish additional Linux/WAN throughput, endurance, or minimum-hardware results.
