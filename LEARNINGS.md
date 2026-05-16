# LEARNINGS — terraform-aws-auth-cognito

Append-only log of non-obvious gotchas specific to this module.
Ecosystem-wide learnings go in `flo-docs/LEARNINGS.md`.

## How to add an entry

```md
## YYYY-MM-DD: <short, specific title>

**Context:** What you were trying to do.
**Symptom:** What broke or surprised you.
**Cause:** Why it broke.
**Resolution:** What you did.
**Codified in:** Where enforced now.
**References:** PRs / issues.
```

---

## 2026-05-16: Heredoc inside ternary conditional is invalid HCL

**Context:** Adding a branded HTML invite email. Used a ternary to conditionally produce HTML when `var.ses_source_arn != null`.

**Symptom:** `terraform validate` (and CI plan) failed: `Error: Missing false expression in conditional`.

**Cause:** Terraform does not allow a heredoc (`<<-HTML`) as either arm of a ternary `? :` expression.

**Resolution:** Extract the heredoc into its own unconditional `local`. The conditional is unnecessary — Cognito ignores the `invite_message_action.email_message` HTML field when the pool is in `COGNITO_DEFAULT` email mode.

**Codified in:** `.cursor/rules/workflow.mdc` (HCL gotchas).

**References:** PR #5

---

## 2026-05-16: Nested interpolation inside heredoc requires a local

**Context:** Trying to embed `${var.logo_url != null ? "<img ...>" : "<span ...>"}` directly inside the invite email heredoc.

**Symptom:** Terraform parse error — nested ternary inside heredoc interpolation is not valid.

**Resolution:** Extract the expression into `local._logo_html`, then reference `${local._logo_html}` inside the heredoc.

**Codified in:** `.cursor/rules/workflow.mdc`.

**References:** PR #5
