variable "region" {
  description = "Deployment region."
  type        = string
  default     = "eu-west-2"
}

variable "instance_type" {
  description = <<-EOT
    Fixed-performance instance type. Must NOT be burstable (t2/t3/t4g) or a
    -flex variant: those accrue CPU credits while idle and change behaviour
    when spending them. A honeypot is idle and then hit hard during a scan --
    precisely when that shift happens -- which would inject uncontrolled
    variance into the latency measurement the project depends on.
  EOT
  type        = string
  default     = "c7i.large"

  validation {
    condition     = !can(regex("^(t[0-9]|.*-flex)", var.instance_type))
    error_message = "Burstable (t*) and -flex instance types are not permitted: variable CPU performance contaminates the latency measurement."
  }
}

variable "ssh_cidr" {
  description = "Single source address permitted to reach SSH. Never 0.0.0.0/0."
  type        = string

  validation {
    condition     = var.ssh_cidr != "0.0.0.0/0"
    error_message = "SSH must not be open to the internet."
  }
}

variable "ssh_public_key" {
  description = <<-EOT
    Optional SSH public key material. If empty, no key pair is created and
    the instance is reachable only via SSM/console -- the security group
    still restricts 22 to ssh_cidr.
  EOT
  type        = string
  default     = ""
}

variable "billing_alarm_threshold_usd" {
  description = <<-EOT
    CloudWatch billing alarm threshold, in USD. Set ABOVE expected spend
    (~$73/month at c7i.large) so that the alarm firing means something has
    actually gone wrong, rather than firing mid-collection simply because
    the deployment is running as intended.
  EOT
  type        = number
  default     = 80
}

variable "alarm_email" {
  description = "Optional address subscribed to the billing alarm topic."
  type        = string
  default     = ""
}

variable "root_volume_gb" {
  description = "Root EBS volume size. Sized for collected logs between S3 shipments."
  type        = number
  default     = 30
}

variable "log_ship_interval_minutes" {
  description = <<-EOT
    How often collected logs are synced to S3. The access log's roll_keep in
    proxy/caddy.json is sized against this: a roll must never discard data
    that has not shipped yet.
  EOT
  type        = number
  default     = 5
}

variable "enable_generation_harness" {
  description = <<-EOT
    When true, installs and enables chameleon-generate.service: a systemd
    unit that runs generation/generate.py against
    generation/run_manifest_stage4.yml on boot, restarting on failure
    (bounded by StartLimitBurst, so a persistently-timing-out run doesn't
    loop forever) but not after a clean exit. This is what makes the
    generation harness survive an instance reboot -- unlike a laptop
    suspend, an EC2 reboot delivers SIGTERM, which generate.py's own
    handler now turns into a clean shutdown (Caddy context reset, engine
    resumed) before systemd relaunches it into the same --checkpoint file.
    False (default) leaves the live-collection instance's user_data
    completely unchanged.
  EOT
  type        = bool
  default     = false
}

variable "probe_rate" {
  description = <<-EOT
    Timing probe rate for the deployed stack. Deploys at 0.0 (inert) by
    decision: the probe is enabled later, once live session-length
    distributions are known.
  EOT
  type        = number
  default     = 0.0

  validation {
    condition     = var.probe_rate >= 0.0 && var.probe_rate <= 1.0
    error_message = "probe_rate must be between 0.0 and 1.0."
  }
}
