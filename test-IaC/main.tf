# main.tf
resource "aws_s3_bucket" "example" {
  bucket = "my-test-bucket"
  acl    = "public-read" # Triggers a Checkov finding
}
