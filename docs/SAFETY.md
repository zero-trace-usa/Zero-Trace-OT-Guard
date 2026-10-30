# OT Safety and Authorization

## Default operating mode
Offline analysis does not initiate network traffic. It processes user-supplied evidence only. Do not capture traffic without organizational authorization. Captures may contain sensitive operational data; store and handle them accordingly.

## Active checks
Active TCP checks require explicit flags, a JSON approval with exact host/port scope, UTC expiry, operator, ticket, connection cap and delay. Dry run is default. A fixed blocklist prevents connections to selected industrial protocol ports. The blocklist is **not comprehensive** and cannot identify OT devices using nonstandard ports. The approval is HMAC-SHA256 signed with a separately provisioned shared key, and execution must match the reviewed plan identifier. Shared-key integrity does not establish independent approver identity. Signed connection budgets, expiry checks, a failure cutoff and cooperative stopping constrain each invocation. Do not mistake it for enterprise change-management integration.

## Site acceptance gates
- Written asset-owner and plant-operations authorization and a documented maintenance window.
- Hazard analysis (including safety instrumented systems and fragile legacy devices).
- Lab validation on representative controllers, network equipment and firmware.
- Approved IP/port allowlists and independently enforced segmentation.
- Baseline network health, packet loss and process stability measurements.
- Human operator at console, emergency-stop and rollback procedure.
- Independent code review, dependency review and security testing.
- Observe operational effects and obtain written approval before widening scope.

**Do not use on live industrial control equipment until these gates are satisfied.**

See [the operator runbook](SAFETY_ENGINE.md) and [settings reference](CONFIGURATION.md) for exact controls and limitations.
