terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = ">= 4.63.0"
      configuration_aliases = [aws.us-east-1, aws.eu-central-1, aws.eu-north-1]
    }
  }
}

locals {
  config_bucket_name = format("config-service-%s", sha1(var.environment_id))
}

locals {
  # https://docs.aws.amazon.com/config/latest/APIReference/API_ResourceIdentifier.html#config-Type-ResourceIdentifier-resourceType
  config_resource_types = [
    "AWS::EC2::CustomerGateway", "AWS::EC2::EIP", "AWS::EC2::Host", "AWS::EC2::Instance", "AWS::EC2::InternetGateway", "AWS::EC2::NetworkAcl", "AWS::EC2::RouteTable", "AWS::CloudTrail::Trail", "AWS::EC2::Volume", "AWS::EC2::VPNConnection", "AWS::EC2::VPNGateway", "AWS::EC2::RegisteredHAInstance", "AWS::EC2::NatGateway", "AWS::EC2::EgressOnlyInternetGateway", "AWS::EC2::VPCEndpoint", "AWS::EC2::VPCEndpointService", "AWS::EC2::FlowLog", "AWS::EC2::VPCPeeringConnection", "AWS::Elasticsearch::Domain", "AWS::IAM::Group", "AWS::IAM::Policy", "AWS::IAM::Role", "AWS::IAM::User", "AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::ACM::Certificate", "AWS::RDS::DBInstance", "AWS::RDS::DBSubnetGroup", "AWS::RDS::DBSecurityGroup", "AWS::RDS::DBSnapshot", "AWS::RDS::DBCluster", "AWS::RDS::DBClusterSnapshot", "AWS::RDS::EventSubscription", "AWS::S3::Bucket", "AWS::S3::AccountPublicAccessBlock", "AWS::Redshift::Cluster", "AWS::Redshift::ClusterSnapshot", "AWS::Redshift::ClusterParameterGroup", "AWS::Redshift::ClusterSecurityGroup", "AWS::Redshift::ClusterSubnetGroup", "AWS::Redshift::EventSubscription", "AWS::SSM::ManagedInstanceInventory", "AWS::CloudWatch::Alarm", "AWS::CloudFormation::Stack", "AWS::ElasticLoadBalancing::LoadBalancer", "AWS::AutoScaling::AutoScalingGroup", "AWS::AutoScaling::LaunchConfiguration", "AWS::AutoScaling::ScalingPolicy", "AWS::AutoScaling::ScheduledAction", "AWS::DynamoDB::Table", "AWS::CodeBuild::Project", "AWS::WAF::RateBasedRule", "AWS::WAF::Rule", "AWS::WAF::RuleGroup", "AWS::WAF::WebACL", "AWS::WAFRegional::RateBasedRule", "AWS::WAFRegional::Rule", "AWS::WAFRegional::RuleGroup", "AWS::WAFRegional::WebACL", "AWS::CloudFront::Distribution", "AWS::CloudFront::StreamingDistribution", "AWS::Lambda::Function", "AWS::NetworkFirewall::Firewall", "AWS::NetworkFirewall::FirewallPolicy", "AWS::NetworkFirewall::RuleGroup", "AWS::ElasticBeanstalk::Application", "AWS::ElasticBeanstalk::ApplicationVersion", "AWS::ElasticBeanstalk::Environment", "AWS::WAFv2::WebACL", "AWS::WAFv2::RuleGroup", "AWS::WAFv2::IPSet", "AWS::WAFv2::RegexPatternSet", "AWS::WAFv2::ManagedRuleSet", "AWS::XRay::EncryptionConfig", "AWS::SSM::AssociationCompliance", "AWS::SSM::PatchCompliance", "AWS::Shield::Protection", "AWS::ShieldRegional::Protection", "AWS::Config::ConformancePackCompliance", "AWS::Config::ResourceCompliance", "AWS::ApiGateway::Stage", "AWS::ApiGateway::RestApi", "AWS::ApiGatewayV2::Stage", "AWS::ApiGatewayV2::Api", "AWS::CodePipeline::Pipeline", "AWS::ServiceCatalog::CloudFormationProvisionedProduct", "AWS::ServiceCatalog::CloudFormationProduct", "AWS::ServiceCatalog::Portfolio", "AWS::SQS::Queue", "AWS::KMS::Key", "AWS::QLDB::Ledger", "AWS::SecretsManager::Secret", "AWS::SNS::Topic", "AWS::SSM::FileData", "AWS::Backup::BackupPlan", "AWS::Backup::BackupSelection", "AWS::Backup::BackupVault", "AWS::Backup::RecoveryPoint", "AWS::ECR::Repository", "AWS::ECS::Cluster", "AWS::ECS::Service", "AWS::ECS::TaskDefinition", "AWS::EFS::AccessPoint", "AWS::EFS::FileSystem", "AWS::EKS::Cluster", "AWS::OpenSearch::Domain", "AWS::EC2::TransitGateway", "AWS::Kinesis::Stream", "AWS::Kinesis::StreamConsumer", "AWS::CodeDeploy::Application", "AWS::CodeDeploy::DeploymentConfig", "AWS::CodeDeploy::DeploymentGroup", "AWS::EC2::LaunchTemplate", "AWS::ECR::PublicRepository", "AWS::GuardDuty::Detector", "AWS::EMR::SecurityConfiguration", "AWS::SageMaker::CodeRepository"
  ]
}

# module "config_eu_central_1" {
#   source                        = "s3::https://s3-eu-central-1.amazonaws.com/terraform-modules-9d7e951c290ec5bbe6506e0ddb064808764bc636/terraform-modules.zip//security/config/v1"
#   name                          = "config-eu-central-1"
#   iam_role_arn                  = module.config_role.iam_role_arn
#   all_supported                 = var.config_record_all_supported
#   include_global_resource_types = false
#   s3_bucket_name                = module.config_bucket.s3_bucket_id
#   resource_types                = var.config_record_all_supported ? [] : local.config_resource_types
#   providers = {
#     aws.this = aws.eu-central-1
#   }
# }

# module "config_us_east_1" {
#   source                        = "s3::https://s3-eu-central-1.amazonaws.com/terraform-modules-9d7e951c290ec5bbe6506e0ddb064808764bc636/terraform-modules.zip//security/config/v1"
#   name                          = "config-us-east-1"
#   iam_role_arn                  = module.config_role.iam_role_arn
#   all_supported                 = var.config_record_all_supported
#   include_global_resource_types = false
#   s3_bucket_name                = module.config_bucket.s3_bucket_id
#   resource_types                = var.config_record_all_supported ? [] : local.config_resource_types
#   providers = {
#     aws.this = aws.us-east-1
#   }
# }

# module "config_eu_north_1" {
#   source                        = "s3::https://s3-eu-central-1.amazonaws.com/terraform-modules-9d7e951c290ec5bbe6506e0ddb064808764bc636/terraform-modules.zip//security/config/v1"
#   name                          = "config-eu-north-1"
#   iam_role_arn                  = module.config_role.iam_role_arn
#   all_supported                 = var.config_record_all_supported
#   include_global_resource_types = false
#   s3_bucket_name                = module.config_bucket.s3_bucket_id
#   resource_types                = var.config_record_all_supported ? [] : local.config_resource_types
#   providers = {
#     aws.this = aws.eu-north-1
#   }
# }

# S3 bucket used to store the configuration history
module "config_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "3.14.0"

  bucket                   = local.config_bucket_name
  control_object_ownership = true
  object_ownership         = "ObjectWriter"

  versioning = {
    enabled = true
  }

  logging = {
    target_bucket = var.logging_bucket_id
    target_prefix = local.config_bucket_name
  }

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }

  // S3 bucket-level Public Access Block configuration
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  tags = var.tags

  providers = {
    aws = aws.eu-central-1
  }
}

data "aws_iam_policy_document" "config" {
  statement {
    sid = "S3Bucket"
    actions = [
      "s3:GetBucketAcl",
      "s3:ListBucket",
    ]
    resources = ["arn:aws:s3:::${module.config_bucket.s3_bucket_id}"]
  }
  statement {
    sid = "S3Objects"
    actions = [
      "s3:PutObject"
    ]
    resources = ["arn:aws:s3:::${module.config_bucket.s3_bucket_id}/*"]
    condition {
      test     = "StringLike"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
  statement {
    sid = "ConfigRead"
    actions = [
      "ecs:ListTaskDefinitionFamilies",
      "ecs:ListTaskDefinitions",
    ]
    resources = [
      "*",
    ]
  }
}

resource "aws_iam_policy" "config" {
  provider    = aws.eu-central-1
  name_prefix = "config_"
  description = "AWS Config"
  path        = "/"
  policy      = data.aws_iam_policy_document.config.json
  tags        = var.tags
  lifecycle {
    create_before_destroy = true
  }
}

module "config_role" {
  source            = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version           = "5.6.0"
  create_role       = true
  role_requires_mfa = false
  role_name         = "config"
  role_description  = "AWS Config"
  trusted_role_services = [
    "config.amazonaws.com",
  ]
  custom_role_policy_arns = [
    aws_iam_policy.config.arn,
    "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole",
  ]
  number_of_custom_role_policy_arns = 2

  tags = var.tags

  providers = {
    aws = aws.eu-central-1
  }
}

module "config_us_east_1" {
  source       = "s3::https://s3-eu-central-1.amazonaws.com/terraform-modules-dacef8339fbd41ce31c346f854a85d0c74f7c4e8/terraform-modules.zip//security/config/v2"
  name         = "config-us-east-1"
  iam_role_arn = module.config_role.iam_role_arn

  include_global_resource_types = true

  s3_bucket_name = module.config_bucket.s3_bucket_id
  providers = {
    aws = aws.us-east-1
  }
}

module "config_eu_central_1" {
  source       = "s3::https://s3-eu-central-1.amazonaws.com/terraform-modules-dacef8339fbd41ce31c346f854a85d0c74f7c4e8/terraform-modules.zip//security/config/v2"
  name         = "config-eu-central-1"
  iam_role_arn = module.config_role.iam_role_arn

  excludes = {
    vpc_ec2_eni      = var.config_record_all_supported ? false : true
    config_resources = var.config_record_all_supported ? false : true
  }

  s3_bucket_name = module.config_bucket.s3_bucket_id
  providers = {
    aws = aws.eu-central-1
  }
}

module "config_eu_north_1" {
  source       = "s3::https://s3-eu-central-1.amazonaws.com/terraform-modules-dacef8339fbd41ce31c346f854a85d0c74f7c4e8/terraform-modules.zip//security/config/v2"
  name         = "config-eu-north-1"
  iam_role_arn = module.config_role.iam_role_arn

  excludes = {
    vpc_ec2_eni      = var.config_record_all_supported ? false : true
    config_resources = var.config_record_all_supported ? false : true
  }

  s3_bucket_name = module.config_bucket.s3_bucket_id
  providers = {
    aws = aws.eu-north-1
  }
}
