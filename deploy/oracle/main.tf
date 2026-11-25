terraform {
  required_version = ">= 1.3.0"
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5.0"
    }
  }
}

provider "oci" {
  region = var.region
}

data "oci_identity_availability_domains" "ads" {
  compartment_id = var.tenancy_ocid
}

data "oci_core_images" "ubuntu" {
  compartment_id           = var.compartment_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "24.04"
  shape                    = var.instance_shape
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
}

resource "random_password" "relay_auth_secret" {
  count   = var.relay_auth_secret == "" ? 1 : 0
  length  = 48
  special = false
}

locals {
  effective_auth_secret = var.relay_auth_secret != "" ? var.relay_auth_secret : random_password.relay_auth_secret[0].result
  effective_ad          = var.availability_domain != "" ? var.availability_domain : data.oci_identity_availability_domains.ads.availability_domains[0].name
}

resource "oci_core_vcn" "relay_vcn" {
  compartment_id = var.compartment_ocid
  cidr_blocks    = ["10.42.0.0/16"]
  display_name   = "${var.name_prefix}-vcn"
  dns_label      = "tendrilrelay"
}

resource "oci_core_internet_gateway" "relay_igw" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.relay_vcn.id
  display_name   = "${var.name_prefix}-igw"
  enabled        = true
}

resource "oci_core_default_route_table" "relay_rt" {
  manage_default_resource_id = oci_core_vcn.relay_vcn.default_route_table_id
  display_name               = "${var.name_prefix}-rt"

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.relay_igw.id
  }
}

resource "oci_core_security_list" "relay_sl" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.relay_vcn.id
  display_name   = "${var.name_prefix}-sl"

  egress_security_rules {
    protocol    = "all"
    destination = "0.0.0.0/0"
  }

  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options {
      min = 443
      max = 443
    }
  }

  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options {
      min = 80
      max = 80
    }
  }

  dynamic "ingress_security_rules" {
    for_each = var.ssh_public_key != "" ? [1] : []
    content {
      protocol = "6"
      source   = var.ssh_cidr
      tcp_options {
        min = 22
        max = 22
      }
    }
  }
}

resource "oci_core_subnet" "relay_subnet" {
  compartment_id    = var.compartment_ocid
  vcn_id            = oci_core_vcn.relay_vcn.id
  cidr_block        = "10.42.1.0/24"
  display_name      = "${var.name_prefix}-subnet"
  dns_label         = "relaysubnet"
  security_list_ids = [oci_core_security_list.relay_sl.id]
}

locals {
  cloud_init_script = <<-EOF
    #!/usr/bin/env bash
    set -euo pipefail

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq podman caddy curl

    RELAY_HOST='${lower(var.relay_domain)}'
    if [ -z "$RELAY_HOST" ]; then
      PUBLIC_IP=$(curl -fsSL --retry 5 --retry-delay 2 https://checkip.amazonaws.com | tr -d '[:space:]')
      if ! [[ "$PUBLIC_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "failed to detect valid public IPv4 address: $PUBLIC_IP" >&2
        exit 1
      fi
      RELAY_HOST="$(printf '%s' "$PUBLIC_IP" | tr '.' '-').sslip.io"
    fi

    install -d -m 0700 /etc/tendril-relay
    install -m 0600 /dev/null /etc/tendril-relay/auth.secret
    printf '%s' '${base64encode(local.effective_auth_secret)}' | base64 -d > /etc/tendril-relay/auth.secret
    chown 65532:65532 /etc/tendril-relay/auth.secret

    cat > /etc/systemd/system/tendril-relay.service <<SERVICE
    [Unit]
    Description=Tendril stateless WebSocket relay
    After=network-online.target
    Wants=network-online.target

    [Service]
    Restart=always
    RestartSec=3
    ExecStartPre=-/usr/bin/podman rm -f tendril-relay
    ExecStart=/usr/bin/podman run --rm --name tendril-relay \
      --user 65532:65532 \
      --network=host \
      --read-only \
      --cap-drop=ALL \
      -v /etc/tendril-relay/auth.secret:/run/secrets/auth.secret:ro \
      ${var.relay_image} \
      --listen 127.0.0.1:8443 \
      --host "$RELAY_HOST" \
      --trusted-proxy 127.0.0.1/32 \
      --auth-secret-file /run/secrets/auth.secret
    ExecStop=/usr/bin/podman stop -t 5 tendril-relay

    [Install]
    WantedBy=multi-user.target
    SERVICE

    cat > /etc/caddy/Caddyfile <<CADDY
    $RELAY_HOST {
      reverse_proxy 127.0.0.1:8443
    }
    CADDY

    if command -v iptables >/dev/null 2>&1; then
      iptables -I INPUT 1 -p tcp --dport 80 -j ACCEPT || true
      iptables -I INPUT 1 -p tcp --dport 443 -j ACCEPT || true
      if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save || true
      elif [ -d /etc/iptables ]; then
        iptables-save > /etc/iptables/rules.v4 || true
      fi
    fi

    systemctl daemon-reload
    systemctl enable --now tendril-relay
    systemctl restart caddy
  EOF
}

resource "oci_core_instance" "relay_vm" {
  availability_domain = local.effective_ad
  compartment_id      = var.compartment_ocid
  display_name        = var.name_prefix
  shape               = var.instance_shape

  dynamic "shape_config" {
    for_each = can(regex("Flex$", var.instance_shape)) ? [1] : []
    content {
      ocpus         = var.flex_ocpus
      memory_in_gbs = var.flex_memory_gb
    }
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.relay_subnet.id
    assign_public_ip = true
    display_name     = "${var.name_prefix}-vnic"
  }

  source_details {
    source_type = "image"
    source_id   = data.oci_core_images.ubuntu.images[0].id
  }

  metadata = merge(
    {
      user_data = base64encode(local.cloud_init_script)
    },
    var.ssh_public_key != "" ? { ssh_authorized_keys = var.ssh_public_key } : {}
  )
}
