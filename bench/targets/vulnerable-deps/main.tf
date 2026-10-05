resource "aws_s3_bucket" "public" {
  bucket = "pencheff-bench-vuln"
  acl    = "public-read"
}

resource "aws_db_instance" "bad" {
  allocated_storage    = 10
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t2.micro"
  name                 = "mydb"
  username             = "root"
  password             = "plaintextpassword"
  storage_encrypted    = false
  publicly_accessible  = true
  skip_final_snapshot  = true
}

resource "aws_security_group" "open_ssh" {
  name        = "pencheff-bench-open-ssh"
  description = "deliberately open"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
