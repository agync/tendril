variable "tenancy_ocid" {
  type        = string
  description = "OCI tenancy OCID (supplied automatically by OCI Resource Manager)."
}

variable "compartment_ocid" {
  type        = string
  description = "OCI compartment OCID (supplied automatically by OCI Resource Manager)."
}

variable "region" {
  type        = string
  description = "OCI region identifier (for example us-ashburn-1 or eu-frankfurt-1)."
}

variable "availability_domain" {
  type        = string
  default     = ""
  description = "Optional availability domain name. Defaults to the first availability domain in the tenancy."
}

variable "name_prefix" {
  type        = string
  default     = "tendril-relay"
  description = "Display name prefix for created OCI resources."

  validation {
    condition     = can(regex("^[A-Za-z0-9-]+$", var.name_prefix))
    error_message = "name_prefix must contain only ASCII letters, digits, and hyphens."
  }
}

variable "instance_shape" {
  type        = string
  default     = "VM.Standard.E2.1.Micro"
  description = "OCI Always Free compute shape (VM.Standard.E2.1.Micro or VM.Standard.A1.Flex)."
}

variable "flex_ocpus" {
  type        = number
  default     = 1
  description = "OCPU count when instance_shape is a Flex shape."
}

variable "flex_memory_gb" {
  type        = number
  default     = 6
  description = "Memory in GB when instance_shape is a Flex shape."
}

variable "relay_domain" {
  type        = string
  default     = ""
  description = "Optional DNS hostname pointing at the VM public IP. Leave blank to use automatic <ip>.sslip.io HTTPS via Caddy."

  validation {
    condition     = (var.relay_domain == "") || (length(var.relay_domain) <= 253 && can(regex("^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$", var.relay_domain)))
    error_message = "relay_domain must be empty or a valid DNS hostname without scheme, port, path, leading hyphen, or trailing dot."
  }
}

variable "relay_image" {
  type        = string
  default     = "ghcr.io/agync/tendril-relay:latest"
  description = "OCI container image reference for tendril-relay."

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._/@:-]*$", var.relay_image))
    error_message = "relay_image must be a valid container image reference."
  }
}

variable "relay_auth_secret" {
  type        = string
  default     = ""
  sensitive   = true
  description = "Shared HMAC admission secret. Leave blank to generate a random 48-character secret."

  validation {
    condition     = var.relay_auth_secret == "" || (length(base64encode(var.relay_auth_secret)) <= 5464 && trimspace(var.relay_auth_secret) == var.relay_auth_secret)
    error_message = "relay_auth_secret must be empty or <= 4096 UTF-8 bytes with no leading/trailing whitespace."
  }
}

variable "ssh_public_key" {
  type        = string
  default     = ""
  description = "Optional SSH public key. Leave blank to disable port 22 ingress."
}

variable "ssh_cidr" {
  type        = string
  default     = "0.0.0.0/0"
  description = "Source CIDR allowed for SSH when ssh_public_key is set."
}
