# Cloud Methodology (AWS / Azure / GCP)

## Recon
- Public S3/GCS/Azure Blob discovery: `s3-buckets-bruteforcer`, `cloud_enum`
- IAM enumeration: `enumerate-iam`, `pacu`, `ScoutSuite`
- Subdomain takeover via dangling DNS to cloud services

## AWS
- IMDSv1 SSRF → STS credentials → assume role chain
- IAM privesc: `iam:PassRole`, `iam:CreateAccessKey`, `lambda:UpdateFunctionCode`
- S3: public ACL, broken bucket policy, object ACL
- CloudFront/Lambda@Edge cache poisoning

## Azure
- Storage account public containers, SAS token abuse
- Managed identity → token from `169.254.169.254/metadata/identity/oauth2/token`
- Entra ID (Azure AD): consent phishing, illicit consent grants
- ARM template injection

## GCP
- IAM: `iam.serviceAccounts.actAs`, `iam.serviceAccountKeys.create`
- Compute metadata token at `metadata.google.internal`
- GKE workload identity abuse

## Tools
- `aws cli`, `pacu`, `ScoutSuite`, `prowler`
- `azure-cli`, `MicroBurst`, `ROADtools`
- `gcloud`, `gcp_scanner`, `GCPBucketBrute`
