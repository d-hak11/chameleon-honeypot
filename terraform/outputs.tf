locals {
  # Static on-demand estimates for eu-west-2, USD, 730h/month. These are a
  # planning aid printed at plan time, not a billing guarantee -- the
  # CloudWatch alarm is the actual control.
  hourly_by_type = {
    "c7i.large"  = 0.0952
    "c7i.xlarge" = 0.1904
    "m7i.large"  = 0.1075
    "m7i.xlarge" = 0.2150
  }

  instance_hourly  = lookup(local.hourly_by_type, var.instance_type, 0.10)
  instance_monthly = local.instance_hourly * 730
  ebs_monthly      = var.root_volume_gb * 0.0928 # gp3, eu-west-2
  s3_monthly       = 1.0                         # telemetry volume is small
  estimated_total  = local.instance_monthly + local.ebs_monthly + local.s3_monthly
}

output "estimated_monthly_cost_usd" {
  description = "Static estimate: instance + root EBS + modest S3. No NAT Gateway."
  value = format(
    "~$%.2f/month (%s $%.2f + %dGB gp3 $%.2f + S3 ~$%.2f). Billing alarm at $%.0f.",
    local.estimated_total,
    var.instance_type,
    local.instance_monthly,
    var.root_volume_gb,
    local.ebs_monthly,
    local.s3_monthly,
    var.billing_alarm_threshold_usd,
  )
}

output "billing_alarm_headroom" {
  description = "How long the alarm threshold lasts at the estimated burn rate."
  value = format(
    "$%.0f threshold / $%.2f per month = alarm fires around day %d of a full month.",
    var.billing_alarm_threshold_usd,
    local.estimated_total,
    floor(var.billing_alarm_threshold_usd / (local.estimated_total / 30)),
  )
}

output "public_ip" {
  description = "Honeypot address. This is what gets scanned."
  value       = aws_instance.honeypot.public_ip
}

output "telemetry_bucket" {
  description = "Private, versioned bucket receiving collected data."
  value       = aws_s3_bucket.telemetry.id
}

output "ssh_command" {
  description = "Administrative access (restricted to ssh_cidr by the security group)."
  value       = "ssh ec2-user@${aws_instance.honeypot.public_ip}"
}

output "probe_rate_deployed" {
  description = "Timing probe rate baked into the deployed config."
  value       = var.probe_rate
}
