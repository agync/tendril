# Tendril Relay on Oracle Cloud Always Free

Provision an Oracle Cloud Always Free VM (`VM.Standard.E2.1.Micro` by default, or `VM.Standard.A1.Flex`) running `tendril-relay` in an unprivileged Podman container (`65532:65532`, `--read-only`, `--cap-drop=ALL`) behind Caddy automatic HTTPS.

## Deploy with OCI Resource Manager or Terraform

1. Package the files in `deploy/oracle/` into a ZIP archive and upload it as an OCI Resource Manager Stack (or point Resource Manager directly at this folder in a forked repository).
2. Leave `relay_domain` blank for automatic Let's Encrypt TLS on `<public_ip>.sslip.io`, or supply a domain whose `A` record points at the instance after creation.
3. Leave `relay_auth_secret` blank to generate a random 48-character secret readable from the Terraform output `relay_auth_secret` (configured on the VM as a `0600` file for `--auth-secret-file`).

> [!NOTE]
> Oracle Cloud Always Free accounts require a valid payment card for identity verification, even when all resources remain within Always Free quotas. Use OpenTofu (`tofu apply`) or Terraform (`terraform apply`) locally if deploying outside the OCI console UI.
