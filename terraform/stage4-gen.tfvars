# Stage 4 generation-matrix instance -- throwaway, workspace "stage4-gen".
# Separate state, separate random_id.suffix, therefore its own S3 bucket and
# its own IAM role scoped only to that bucket (see main.tf's telemetry_rw
# policy: every resource ARN in it derives from THIS apply's
# aws_s3_bucket.telemetry, never a hardcoded name) -- structurally isolated
# from the live-collection instance's bucket and data, not isolated by
# convention alone.
enable_generation_harness = true
