output "public_ip" {
  description = "Public IPv4 address of the Always Free relay VM."
  value       = oci_core_instance.relay_vm.public_ip
}

output "relay_host" {
  description = "Configured relay hostname bound into challenge signatures."
  value       = var.relay_domain != "" ? lower(var.relay_domain) : "${replace(oci_core_instance.relay_vm.public_ip, ".", "-")}.sslip.io"
}

output "relay_v1_url" {
  description = "WebSocket URL for /v1/relay clients."
  value       = "wss://${var.relay_domain != "" ? lower(var.relay_domain) : "${replace(oci_core_instance.relay_vm.public_ip, ".", "-")}.sslip.io"}/v1/relay"
}

output "relay_v2_url" {
  description = "WebSocket URL for /v2/relay clients."
  value       = "wss://${var.relay_domain != "" ? lower(var.relay_domain) : "${replace(oci_core_instance.relay_vm.public_ip, ".", "-")}.sslip.io"}/v2/relay"
}

output "relay_auth_secret" {
  description = "Configured TENDRIL_RELAY_AUTH_SECRET for Tendril clients and hosts."
  value       = local.effective_auth_secret
  sensitive   = true
}
