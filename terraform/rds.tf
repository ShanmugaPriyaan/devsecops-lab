# FLAW: unencrypted database. Off by default because RDS costs money:
#   terraform apply -var create_rds=true -var db_password='<choose one>'
# Destroy it (and any snapshots you make) the same day.

variable "create_rds" {
  type    = bool
  default = false
}

variable "db_password" {
  type      = string
  sensitive = true
  default   = null
}

resource "aws_db_instance" "unencrypted" {
  count               = var.create_rds ? 1 : 0
  identifier          = "cspm-lab-unencrypted-db"
  engine              = "postgres"
  instance_class      = "db.t4g.micro"
  allocated_storage   = 20
  username            = "labadmin"
  password            = var.db_password
  storage_encrypted   = false
  publicly_accessible = false
  skip_final_snapshot = true
}
