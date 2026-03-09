# GCP Credential Security Best Practices

> Source: Google Cloud email — "[Action Advised] Review Google Cloud credential security best practices" (2026-03-09)

Recent security trends indicate that long-lived credentials without proper security best practices remain a top security risk for unauthorized access. To modernize your authentication strategy, implement the unified security framework outlined below.

---

## Secure the Credential Lifecycle

### Zero-Code Storage
Never commit keys to source code or version control. Use [Secret Manager](https://cloud.google.com/secret-manager) to inject credentials at runtime.

### Disable Dormant Keys
Audit your active keys and decommission any that show no activity over the last 30 days.

### Enforce API Restrictions
Never leave an API key unrestricted. Limit keys to specific APIs (e.g., Maps JavaScript only) and apply environmental restrictions (IP addresses, HTTP referrers, or bundle IDs).

### Apply Least Privilege
Never give full permissions to a service account. Use the [IAM Recommender](https://cloud.google.com/iam/docs/recommender-overview) to prune unused permissions, ensuring only the absolute minimum access required.

### Mandatory Rotation
Implement the `iam.serviceAccountKeyExpiryHours` policy to enforce a maximum lifespan for all user-managed service account keys. If service account keys are not needed, implement `iam.managed.disableServiceAccountKeyCreation` to disable the creation of new keys.

---

## Improve Operational Safeguards

### Set Essential Contacts
Verify that your [Essential Contacts](https://cloud.google.com/resource-manager/docs/managing-notification-contacts) are up to date to ensure critical security notifications reach the right people during an incident.

### Set Billing Anomaly and Budget Alerts
Ensure billing anomaly and budget alert notifications are acted on. A sudden spike in consumption is often the first indicator of a compromised credential.
