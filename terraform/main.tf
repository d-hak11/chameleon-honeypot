# ---------------------------------------------------------------------------
# Network
#
# The default VPC is used deliberately. The instance needs a public IP and
# outbound internet access, which a default subnet's internet gateway already
# provides. Building a custom VPC with private subnets would require a NAT
# Gateway (~$33/month plus data processing) to give the instance egress --
# for a single public-facing honeypot that is pure cost with no benefit.
# There is no NAT Gateway resource anywhere in this configuration.
# ---------------------------------------------------------------------------

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}

# ---------------------------------------------------------------------------
# Telemetry bucket
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "telemetry" {
  bucket = "chameleon-honeypot-telemetry-${random_id.suffix.hex}"
}

resource "aws_s3_bucket_public_access_block" "telemetry" {
  bucket = aws_s3_bucket.telemetry.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "telemetry" {
  bucket = aws_s3_bucket.telemetry.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "telemetry" {
  bucket = aws_s3_bucket.telemetry.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# The stack source, shipped to the instance via the instance profile rather
# than a git remote -- the honeypot host holds no credentials of any kind.
data "archive_file" "stack" {
  type        = "zip"
  source_dir  = "${path.module}/.."
  output_path = "${path.module}/.build/stack.zip"

  excludes = [
    ".git",
    "secrets", # local salt; production reads its own from S3
    "aws",     # local AWS CLI installer
    "awscliv2.zip",
    "terraform",
    "evidence",
    "__pycache__",
    # Runtime state from a local generation run -- gitignored, but
    # archive_file zips the working directory as-is and does not consult
    # .gitignore, so without this a stale local checkpoint/log would ship
    # to a fresh instance and either resume from the wrong point or get
    # mistaken for that instance's own progress.
    "generation/checkpoint.json",
    "generation/stage4_run.log",
    "generation/generation_log.jsonl",
  ]
}

resource "aws_s3_object" "stack" {
  bucket = aws_s3_bucket.telemetry.id
  key    = "deploy/stack-${data.archive_file.stack.output_md5}.zip"
  source = data.archive_file.stack.output_path
  etag   = data.archive_file.stack.output_md5
}

# ---------------------------------------------------------------------------
# Pseudonymisation salt
#
# Held here rather than generated per-instance. source_hash is only stable
# while the salt is: a regenerated salt makes the same returning attacker
# appear as two unrelated sources across an instance replacement, which
# would silently corrupt repeat_visit_count (and any other cross-session
# feature) in analysis/extract_features.py rather than failing loudly.
#
# Consequence to be aware of: the salt value is stored in Terraform state.
# State is local and gitignored, but it is now secret-bearing -- with both
# the state file and the collected logs, source_hash becomes reversible.
# Treat terraform.tfstate accordingly.
# ---------------------------------------------------------------------------

resource "random_password" "source_salt" {
  length  = 64
  special = false
}

resource "aws_s3_object" "source_salt" {
  bucket       = aws_s3_bucket.telemetry.id
  key          = "secrets/source_salt.env"
  content      = "CHAMELEON_SOURCE_SALT=${random_password.source_salt.result}\n"
  content_type = "text/plain"

  # Never overwrite an existing salt on re-apply: doing so would silently
  # break comparability with everything already collected.
  lifecycle {
    ignore_changes = [content]
  }
}

# ---------------------------------------------------------------------------
# Instance role: write to this one bucket, nothing else
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "honeypot" {
  name               = "chameleon-honeypot-${random_id.suffix.hex}"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

data "aws_iam_policy_document" "telemetry_rw" {
  statement {
    sid    = "ReadStackArtifactAndSalt"
    effect = "Allow"
    actions = [
      "s3:GetObject",
    ]
    resources = [
      "${aws_s3_bucket.telemetry.arn}/deploy/*",
      "${aws_s3_bucket.telemetry.arn}/secrets/source_salt.env",
    ]
  }

  statement {
    sid    = "WriteTelemetry"
    effect = "Allow"
    actions = [
      "s3:PutObject",
    ]
    resources = ["${aws_s3_bucket.telemetry.arn}/telemetry/*"]
  }

  statement {
    sid       = "ListOwnBucketOnly"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.telemetry.arn]
  }
}

resource "aws_iam_role_policy" "telemetry_rw" {
  name   = "telemetry-access"
  role   = aws_iam_role.honeypot.id
  policy = data.aws_iam_policy_document.telemetry_rw.json
}

resource "aws_iam_instance_profile" "honeypot" {
  name = "chameleon-honeypot-${random_id.suffix.hex}"
  role = aws_iam_role.honeypot.name
}

# ---------------------------------------------------------------------------
# Security group
# ---------------------------------------------------------------------------

resource "aws_security_group" "honeypot" {
  name        = "chameleon-honeypot-${random_id.suffix.hex}"
  description = "Honeypot: 80/443 from the internet, SSH from one address only"
  vpc_id      = data.aws_vpc.default.id
}

resource "aws_vpc_security_group_ingress_rule" "http" {
  security_group_id = aws_security_group.honeypot.id
  description       = "Honeypot traffic -- this is the data being collected"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  security_group_id = aws_security_group.honeypot.id
  description       = "Reserved for TLS -- see the TLS note in terraform/README.md"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id = aws_security_group.honeypot.id
  description       = "Administrative access from a single address"
  cidr_ipv4         = var.ssh_cidr
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.honeypot.id
  description       = "Outbound: image pulls and S3 telemetry shipping"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_key_pair" "admin" {
  count      = var.ssh_public_key == "" ? 0 : 1
  key_name   = "chameleon-honeypot-${random_id.suffix.hex}"
  public_key = var.ssh_public_key
}

# ---------------------------------------------------------------------------
# Billing alarm -- created BEFORE the instance (see depends_on below), so
# there is never a window where something is billable and unmonitored.
# ---------------------------------------------------------------------------

resource "aws_sns_topic" "billing" {
  provider = aws.billing
  name     = "chameleon-honeypot-billing-${random_id.suffix.hex}"
}

resource "aws_sns_topic_subscription" "billing_email" {
  provider  = aws.billing
  count     = var.alarm_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.billing.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

resource "aws_cloudwatch_metric_alarm" "billing" {
  provider            = aws.billing
  alarm_name          = "chameleon-honeypot-estimated-charges"
  alarm_description   = "Estimated AWS charges exceeded the configured threshold."
  namespace           = "AWS/Billing"
  metric_name         = "EstimatedCharges"
  dimensions          = { Currency = "USD" }
  statistic           = "Maximum"
  period              = 21600 # 6h; the billing metric updates a few times a day
  evaluation_periods  = 1
  threshold           = var.billing_alarm_threshold_usd
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.billing.arn]
  treat_missing_data  = "notBreaching"
}

# ---------------------------------------------------------------------------
# The honeypot
# ---------------------------------------------------------------------------

resource "aws_instance" "honeypot" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = var.instance_type
  subnet_id              = data.aws_subnets.default.ids[0]
  vpc_security_group_ids = [aws_security_group.honeypot.id]
  iam_instance_profile   = aws_iam_instance_profile.honeypot.name
  key_name               = var.ssh_public_key == "" ? null : aws_key_pair.admin[0].key_name

  associate_public_ip_address = true

  root_block_device {
    volume_size = var.root_volume_gb
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    bucket                    = aws_s3_bucket.telemetry.id
    stack_key                 = aws_s3_object.stack.key
    salt_key                  = aws_s3_object.source_salt.key
    region                    = var.region
    probe_rate                = var.probe_rate
    ship_interval_min         = var.log_ship_interval_minutes
    enable_generation_harness = var.enable_generation_harness
  })

  # Nothing becomes billable until the cost alarm exists.
  depends_on = [
    aws_cloudwatch_metric_alarm.billing,
    aws_s3_object.stack,
    aws_s3_object.source_salt,
  ]

  tags = {
    Name = "chameleon-honeypot"
  }
}

# Remote administration without SSH keys or an open SSH path. The security
# group still restricts 22 to ssh_cidr; this simply means the honeypot host
# needs no key material on it at all, which is the same reason the stack and
# salt arrive via the instance profile.
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.honeypot.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
