# Trufflehog Intelligence v7.14.0 — Generic Asset Licensing & Delivery Intelligence

## New: Network & APIs → Asset Licensing & Delivery Intelligence

Generic analysis of responses *already observed* through an authorised opt-in browser capture. No vendor or agency is hard-coded. The optional DevTools JSON parser recursively classifies nested asset/licence/size/price structures and records only bounded, allowlisted numeric and boolean values plus safe semantic categories. Real IDs are replaced by random anonymous references in the extension DevTools process. The full JSON body is discarded.

### Supported evidence classes

- `LICENSE_METADATA`, `ASSET_METADATA`, `PRICING_METADATA`, `SIZE_CATALOGUE` and `DOWNLOAD_ELIGIBILITY` from explicitly enabled JSON inspection.
- `PREVIEW_DELIVERY`, `DOWNLOAD_REQUEST`, `DOWNLOAD_RESPONSE` from already-observed network metadata. Any media response labelled a delivery is **not** assumed to be a preview of a specific asset.
- `ORIGINAL_DELIVERY_CONFIRMED` is deliberately not asserted from names, dimensions, file responses, or listing alone; proving a native master requires independent file identity and native-resolution provenance unavailable to this passive parser.
- `UNKNOWN` for structures without sufficient evidence.

### Licence, price and size handling

Recursive analysis of nested `children`, `download_sizes`, alternative snake_case/camelCase keys, selectable states, parent relationships, recommended / max size references, advertised size classes, explicitly reported pixel dimensions, price amount/net/gross/base/tax/credits/factors/surcharges, currency, and explicit entitlement flags. Price 0 on a non-selectable parent is **not** a free licence. Only an explicit free flag **plus** a selectable option and positive entitlement flag supports an explicitly-free-indicator label; it still does not prove a successful download.

Anonymous asset references can correlate across already-inspected responses while the same DevTools page stays open; they reset on DevTools reload. Observations from network/download events are never linked to an asset merely by timing proximity.

### Capture & privacy

- Normal site capture: manual per-tab start and site grant; no requests issued by this module.
- JSON licensing: additionally enable **JSON shapes + licensing** in dashboard, open DevTools **on the original inspected tab**, then generate/observe responses. Maximum JSON content length: 256 KiB. Parser caps depth, node and array counts.
- No signed URL values, browser cookies, authorization, credential strings, raw URLs, full JSON, descriptions, filenames, account identifiers, licence IDs or asset IDs appear in the module's persisted record or exported reports.
- Optional Download observer is required to show exact browser download completions. Network HTTP file response ≠ completed Chrome download.
- No new Chrome permissions; v7.13.1's narrow required localhost host permission remains in the manifest. Windows Chrome runtime acceptance remains outstanding, including prior host-permission warning.

### Compatibility

Added optional `licensingObservations` array and a bounded drop counter to schema 19. Older schema 18 captures remain readable; other capture fields and tools are retained. Automated live-record rollover archives licensing entries safely at the same cap approach as other modules. Existing README, run.bat, and local test server are updated. Test fixtures include both the supplied licence-tree concept and deliberately generic alternate schemas.

### Known limitations

- Response-body analysis is only available when DevTools is open and opt-in JSON inspection is enabled; Chrome `webRequest` does not expose response bodies.
- Licensing descriptions and raw restriction text are deliberately discarded; controlled usage categories are retained where possible.
- Native master identity, licensing entitlement enforcement and asset-to-CDN download identity cannot be verified from a listing alone. This feature does not construct or retrieve alternative signed links.
- Live Windows Chrome installed-extension acceptance remains required before final sign-off.
