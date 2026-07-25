# Asset → Owner Registry (template)

A living map of your assets / products to their rightful remediation owners. Ownership is
frequently **not** reliably present in the Wiz API (resource tags are often incomplete, and Wiz
"projects" may be internal scanning scopes rather than the owning team), so maintaining this
registry saves you from re-deriving the owner every time a known asset recurs.

**How to use it**
1. **Before** building a report / raising a ticket, check this table for the affected asset or
   product. If it is listed, surface the recorded owner for the user to confirm.
2. Populate a row from an authoritative source: the resource's `TechnicalOwner` / `Owner` tags,
   a prior incident, or a confirmation from the user. Never guess an owner.
3. **After** each report, add or update the row (and the "Last Confirmed" date).
4. Keep this file local to your environment — it is your organization's data, not part of the
   shareable skill.

| Asset / Product | Type | Technical Owner | Owner Email | Assignment Group | Source | Last Confirmed |
|-----------------|------|-----------------|-------------|------------------|--------|----------------|
| _example-app_ | _Cloud Run service (GCP)_ | _Firstname Lastname_ | _owner@example.com_ | _Your VM group_ | _resource tag / INC# / user_ | _YYYY-MM-DD_ |
|  |  |  |  |  |  |  |

<!-- Add one row per asset or product family. Delete the example row once you have real entries. -->
