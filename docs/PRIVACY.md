# Privacy

PondSec NDR defaults to metadata-only storage.

## Not Stored by Default

- HTTP body
- POST data
- Credentials
- Cookies
- Authorization headers
- Full query parameters
- File contents
- Decrypted payloads
- Form data

## Stored Metadata

The backend stores normalized network metadata needed for detection:

- Timestamp
- Event type
- Source and destination IP/port
- Protocol
- Direction
- Interface when available
- Sanitized DNS, TLS, HTTP, flow, alert, and stats fields

## Anonymization

IP and domain anonymization are represented in configuration and will be enforced in all export flows. The first implementation keeps the sanitizer centralized in the normalizer so data sources can share privacy controls.

## Retention

Retention is configurable. The database layer contains cleanup hooks for event age and database size limits. Operators should keep retention as short as operationally useful.

## Exports

Exports must not contain personal payloads. Future export features must use normalized event records, not raw EVE lines, unless an administrator explicitly enables raw forensic handling.
