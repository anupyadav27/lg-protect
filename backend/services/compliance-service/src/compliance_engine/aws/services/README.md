# AWS Compliance Services - Developer Guide

## 🎯 What You Need to Do

You need to implement **Tier 3** for 71 AWS services by converting them from prowler to BaseService/BaseCheck pattern.

## 📋 Current Status

- ✅ **Tier 1 Complete**: All `__init__.py` and `*_client.py` files are generated
- ✅ **11 Services Complete**: accessanalyzer, account, acm, apigatewayv2, appstream, appsync, athena, autoscaling, awslambda, backup, bedrock
- 🔄 **71 Services Pending**: cloudformation, cloudfront, cloudtrail, cloudwatch, codeartifact, codebuild, cognito, config, datasync, directconnect, directoryservice, dlm, dms, documentdb, drs, dynamodb, ec2, ecr, ecs, efs, eks, elasticache, elasticbeanstalk, elb, elbv2, emr, eventbridge, firehose, fms, fsx, glacier, globalaccelerator, glue, guardduty, iam, inspector2, kafka, kinesis, kms, lightsail, macie, memorydb, mq, neptune, networkfirewall, opensearch, organizations, rds, redshift, resourceexplorer2, route53, s3, sagemaker, secretsmanager, securityhub, servicecatalog, ses, shield, sns, sqs, ssm, ssmincidents, stepfunctions, storagegateway, transfer, trustedadvisor, vpc, waf, wafv2, wellarchitected, workspaces

## 🚀 How to Work

### 1. Use Cursor.ai
- Open this project in Cursor.ai
- Start a conversation with Cursor.ai
- Follow the step-by-step guide in `DEVELOPMENT_GUIDE.md`

### 2. Follow the Process
- Start with one service (e.g., cloudformation)
- Convert service file from prowler to BaseService
- Convert all check files from prowler to BaseCheck
- Run quality checks
- Test implementation
- Move to next service

### 3. Use the Tools
- `quality_assurance.py` - Check quality of your work
- `template_generator.py` - Generate starting templates
- `DEVELOPMENT_GUIDE.md` - Complete development guide

## 🎯 Success Criteria

A service is complete when:
- [ ] Service file uses BaseService pattern
- [ ] All check files use BaseCheck pattern
- [ ] No prowler dependencies remain
- [ ] Quality assurance passes
- [ ] All imports work correctly
- [ ] Tests pass successfully

## 📞 Support

- Read `DEVELOPMENT_GUIDE.md` for complete instructions
- Use the quality assurance tools to check your work
- Look at completed services (bedrock, accessanalyzer, etc.) for examples

**Good luck! You're doing important work! 🚀** 