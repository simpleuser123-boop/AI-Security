# Phase C6 Misblock Recovery SOP

Use this SOP when a real response may have blocked legitimate traffic. The goal is to stop new real enforcement first, restore access quickly, then preserve evidence for review.

## First Action

1. Set `DRY_RUN=true`.
2. Remove or blank `REAL_ENFORCEMENT_GATE`.
3. Restart the response worker/app components that read those environment variables.

Do this before investigating the full root cause. It prevents additional real bans while the team restores service.

## Re-enable Gate

Do not restore `DRY_RUN=false` until every real-enforcement admission item is present again:

- `REAL_ENFORCEMENT_GATE=real-enforcement`.
- `REAL_ENFORCEMENT_APPROVAL_REQUIRED=true`.
- `REAL_ENFORCEMENT_AUDIT_VERIFIED=true`.
- `REAL_ENFORCEMENT_ROLLBACK_READY=true`.
- `REAL_ENFORCEMENT_UNBLOCK_READY=true`.
- `REAL_ENFORCEMENT_REVIEW_REQUIRED=true`.
- Active business/private/control-plane whitelist evidence in `RESPONSE_BUSINESS_IP_WHITELIST` or `response_whitelist_entries`.
- Active provider config in `response_provider_configs` with `last_validated_at` and `last_validation_result.ok=true`.
- Passed recovery drill record in `response_drills` with `ended_at`.

## Recovery Steps

1. Identify the affected IP, response action id, schedule task id, provider, and rule id from `response_actions`, `response_schedule_tasks`, `audit_events`, and `logs/security.log`.
2. Run `rollback_ban` or `manual_unban_ip` with a named operator and reason. If the app path is unavailable, remove the provider rule directly, then record the manual change in the incident ticket.
3. Verify the provider state. For iptables, confirm no matching `DROP` rule remains. For cloud security groups, confirm the Guardian-created deny rule or tagged rule is gone.
4. Add the affected source to the appropriate business/private/control-plane whitelist.
5. Confirm customer traffic, monitoring probes, and console access have recovered.
6. Keep existing `scheduled_unblock` tasks. If the rule is already absent, the task should complete as `skipped` and remain auditable.
7. Archive evidence: response action rows, schedule task rows including `last_error`, audit events, provider operation logs, and the environment change record.
8. Complete post-response review before re-enabling `DRY_RUN=false` or restoring `REAL_ENFORCEMENT_GATE=real-enforcement`.

## Acceptance Evidence

- `DRY_RUN=true` and `REAL_ENFORCEMENT_GATE` removed during containment.
- Manual rollback/unban action has operator, reason, timestamp, and audit event.
- Provider rule is absent or documented as already absent.
- Any failed scheduled unblock has `last_error` and retry history.
- Whitelist update and post-response review are linked to the incident.
