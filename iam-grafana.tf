# Set permissions for cross-account Grafana access
data "aws_iam_policy_document" "cross_account_grafana" {
  statement {
    sid = "Grafana"
    actions = [
      "aps:ListWorkspaces",
      "tag:GetResources",
      "ec2:DescribeTags",
      "ec2:DescribeInstances",
      "ec2:DescribeRegions",
      "logs:GetQueryResults",
      "xray:GetGroups",
      "xray:GetSamplingStatisticSummaries",
      "xray:GetTraceGraph",
      "xray:GetServiceGraph",
      "xray:GetInsightImpactGraph",
      "xray:GetInsightSummaries",
      "xray:GetSamplingTargets",
      "xray:BatchGetTraces",
      "xray:GetTimeSeriesServiceStatistics",
      "xray:GetSamplingRules",
      "xray:GetInsight",
      "xray:GetInsightEvents",
      "xray:GetTraceSummaries",
    ]
    resources = ["*"]
  }
  statement {
    sid = "XRay"
    actions = [
      "xray:ListTagsForResource",
      "xray:GetGroup",
    ]
    resources = [
      "arn:aws:xray:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:group/*/*",
      "arn:aws:xray:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:sampling-rule/*",
    ]
  }
  statement {
    sid = "Prometheus"
    actions = [
      "aps:DescribeWorkspace",
      "aps:QueryMetrics",
      "aps:GetLabels",
      "aps:GetSeries",
      "aps:GetMetricMetadata",
    ]
    resources = [
      "arn:aws:aps:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:workspace/*",
    ]
  }
  statement {
    sid = "CloudWatch"
    actions = [
      "cloudwatch:DescribeAlarmsForMetric",
      "cloudwatch:DescribeAlarmHistory",
      "cloudwatch:DescribeAlarms",
      "cloudwatch:ListMetrics",
      "cloudwatch:GetMetricStatistics",
      "cloudwatch:GetMetricData",
      "cloudwatch:GetInsightRuleReport",
    ]
    resources = [
      "*",
    ]
  }
  statement {
    sid = "CWLogs"
    actions = [
      "logs:DescribeLogGroups",
      "logs:GetLogGroupFields",
      "logs:StartQuery",
      "logs:StopQuery",
      "logs:GetLogEvents",
    ]
    resources = [
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:*",
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:*:log-stream:*",
    ]
  }
}

resource "aws_iam_policy" "cross_account_grafana" {
  name_prefix = "cross_account_grafana_"
  description = "AWS Grafana for Cross Account"
  path        = "/"
  policy      = data.aws_iam_policy_document.cross_account_grafana.json
  tags        = module.tags.result
  lifecycle {
    create_before_destroy = true
  }
}

module "cross_account_grafana" {
  source            = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version           = "4.2.0"
  create_role       = true
  role_requires_mfa = false
  role_name         = "cross_account_grafana"
  role_description  = "AWS Grafana for Cross Account. Access from grafana account"
  trusted_role_arns = [
    "arn:aws:iam::${var.grafana_account_id}:root"
  ]
  custom_role_policy_arns = [
    aws_iam_policy.cross_account_grafana.arn,
  ]
  number_of_custom_role_policy_arns = 1

  tags = module.tags.result
}
