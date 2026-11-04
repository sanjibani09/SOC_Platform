# 10-minute demonstration

1. Sign in using the seeded local administrator and inspect the dashboard.
2. Register a separate analyst account through the API, then use it to verify that admin routes are forbidden.
3. Run the normal simulator and show events in Log Viewer.
4. Run `python simulator/simulate.py --mode bruteforce --count 8 --delay 0.1`; inspect the resulting T1110 alert.
5. Acknowledge, investigate, add a note and resolve the alert.
6. Run off-hours and bulk-file telemetry and inspect the ML/rule reasons.
7. Return to the dashboard and inspect the administrator audit trail.

The demo should be run only against the local synthetic-data environment.
