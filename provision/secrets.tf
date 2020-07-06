variable "FLASK_SECRET_KEY" {
  description = "Secret key for Flask sessions in main app"
}

variable "TWILIO_AUTH_TOKEN" {
  description = "Twilio API key"
}

variable "SENDGRID_API_KEY" {
  description = "SendGrid API key"
}

variable "ADMIN_FLASK_SECRET_KEY" {
  description = "Secret key for Flask sessions in admin app"
}

variable "ADMIN_USERS" {
  description = "Usernames/passwords for access to the admin UI"
}

resource "aws_secretsmanager_secret" "secret-FLASK_SECRET_KEY" {
  name = "FLASK_SECRET_KEY"
}
resource "aws_secretsmanager_secret_version" "secret-FLASK_SECRET_KEY-version" {
  secret_id = aws_secretsmanager_secret.secret-FLASK_SECRET_KEY.id
  secret_string = var.FLASK_SECRET_KEY
}

resource "aws_secretsmanager_secret" "secret-TWILIO_AUTH_TOKEN" {
  name = "TWILIO_AUTH_TOKEN"
}
resource "aws_secretsmanager_secret_version" "secret-TWILIO_AUTH_TOKEN-version" {
  secret_id = aws_secretsmanager_secret.secret-TWILIO_AUTH_TOKEN.id
  secret_string = var.TWILIO_AUTH_TOKEN
}

resource "aws_secretsmanager_secret" "secret-SENDGRID_API_KEY" {
  name = "SENDGRID_API_KEY"
}
resource "aws_secretsmanager_secret_version" "secret-SENDGRID_API_KEY-version" {
  secret_id = aws_secretsmanager_secret.secret-SENDGRID_API_KEY.id
  secret_string = var.SENDGRID_API_KEY
}

resource "aws_secretsmanager_secret" "secret-DATABASE_URL" {
  name = "DATABASE_URL"
}
resource "aws_secretsmanager_secret_version" "secret-DATABASE_URL-version" {
  secret_id = aws_secretsmanager_secret.secret-DATABASE_URL.id
  secret_string = "postgresql://postgres:${var.db_master_password}@${aws_rds_cluster.database.endpoint}/${aws_rds_cluster.database.database_name}"
}

resource "aws_secretsmanager_secret" "secret-REDIS_URL" {
  name = "REDIS_URL"
}
resource "aws_secretsmanager_secret_version" "secret-REDIS_URL-version" {
  secret_id = aws_secretsmanager_secret.secret-REDIS_URL.id
  secret_string = "redis+cluster://${aws_elasticache_replication_group.redis.configuration_endpoint_address}:6379"
}

resource "aws_secretsmanager_secret" "secret-ADMIN_FLASK_SECRET_KEY" {
  name = "ADMIN_FLASK_SECRET_KEY"
}
resource "aws_secretsmanager_secret_version" "secret-ADMIN_FLASK_SECRET_KEY-version" {
  secret_id = aws_secretsmanager_secret.secret-ADMIN_FLASK_SECRET_KEY.id
  secret_string = var.ADMIN_FLASK_SECRET_KEY
}

resource "aws_secretsmanager_secret" "secret-ADMIN_USERS" {
  name = "ADMIN_USERS"
}
resource "aws_secretsmanager_secret_version" "secret-ADMIN_USERS-version" {
  secret_id = aws_secretsmanager_secret.secret-ADMIN_USERS.id
  secret_string = var.ADMIN_USERS
}
