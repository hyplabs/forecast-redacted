resource "aws_route53_zone" "root-domain" {
  name = "forecast.example.com"
}

resource "aws_route53_record" "api-subdomain" {
  zone_id = aws_route53_zone.root-domain.zone_id
  name    = "api.forecast.example.com"
  type    = "CNAME"
  ttl     = "300"
  records = [aws_lb.load-balancer.dns_name]
}

resource "aws_route53_record" "admin-subdomain" {
  zone_id = aws_route53_zone.root-domain.zone_id
  name    = "admin.forecast.example.com"
  type    = "CNAME"
  ttl     = "300"
  records = [aws_lb.load-balancer.dns_name]
}

resource "aws_route53_record" "bastion-subdomain" {
  zone_id = aws_route53_zone.root-domain.zone_id
  name    = "bastion.forecast.example.com"
  type    = "A"
  ttl     = "300"
  records = [aws_eip.bastion-ip-address.public_ip]
}

#################
# HTTPS support #
#################

resource "aws_acm_certificate" "https-certificate" {
  domain_name = "forecast.example.com"
  subject_alternative_names = ["*.forecast.example.com"]
  validation_method = "DNS"
}

resource "aws_route53_record" "https-certificate-proof" {
  name = aws_acm_certificate.https-certificate.domain_validation_options.0.resource_record_name
  type = aws_acm_certificate.https-certificate.domain_validation_options.0.resource_record_type
  zone_id = aws_route53_zone.root-domain.zone_id
  records = [aws_acm_certificate.https-certificate.domain_validation_options.0.resource_record_value]
  ttl = 60
}

resource "aws_acm_certificate_validation" "https-certificate-validation" {
  certificate_arn = aws_acm_certificate.https-certificate.arn
  validation_record_fqdns = [aws_route53_record.https-certificate-proof.fqdn]
}

###########
# OUTPUTS #
###########

output "devhost-login-command" {
  value = "chmod 600 devhost-key.pem; ssh-add devhost-key.pem; ssh -J ec2-user@bastion.forecast.example.com ec2-user@${aws_instance.devhost.private_ip}"
}
