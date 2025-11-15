# Róbert: I'm going to make changes to the code so that it works with newer versions.
--------

# Centralizing AWS EKS Cluster logs to AWS OpenSearch with Fluent Bit
Centralizing AWS EKS Cluster logs to AWS OpenSearch with Fluent Bit

## Architecture
```
EKS Cluster ---Fluent Bit---> AWS Opensearch
```

## Set the necessary environment variables
```bash
# Name of our Amazon OpenSearch cluster
export ES_DOMAIN_NAME="cloudacode-es"

# OpenSearch version
export ES_VERSION="OpenSearch_2.13"

# AWS region and account ID
export AWS_REGION="ap-northeast-2"
export ACCOUNT_ID=$(aws sts get-caller-identity | jq .Account -r)

# OpenSearch Dashboards admin user credentials
export ES_DOMAIN_USER="cloudacode"
export ES_DOMAIN_PASSWORD=$(LC_ALL=C echo "$(tr -dc 'A-Z' < /dev/urandom | head -c1)$(tr -dc 'a-z' < /dev/urandom | head -c1)$(tr -dc '0-9' < /dev/urandom | head -c1)$(tr -dc '!@#$%^&*()_+{}|:<>?=' < /dev/urandom | head -c1)$(tr -dc 'A-Za-z0-9!@#$%^&*()_+{}|:<>?=' < /dev/urandom | head -c8)" | fold -w1 | shuf | tr -d '\n')
```

## Create a OpenSearch Cluster Domain(Public facing)
```bash
# Clone the repository from GitHub
git clone https://github.com/cloudacode/aws-eks-logging-to-opensearch.git

# Run the envsubst command to substitute the values of environment variables into the es_domain.json file, and output the result to a new file es_domain_edited.json
cat ./es_domain.json| envsubst > ./es_domain_edited.json

# Use the AWS CLI to create a new OpenSearch domain, using the JSON file we just created as input
aws opensearch create-domain \
  --cli-input-json  file://es_domain_edited.json

# Use the AWS CLI to check the processing status of the OpenSearch domain
aws opensearch describe-domain --domain-name ${ES_DOMAIN_NAME} --query 'DomainStatus.Processing'

# Use the AWS CLI to get the endpoint of the OpenSearch domain
aws opensearch describe-domain --domain-name ${ES_DOMAIN_NAME} --query 'DomainStatus.Endpoint'

# Export the endpoint of the OpenSearch domain as an environment variable
export ES_ENDPOINT="search-cloudacode-es-hfcixybx5tbsifxfbdffbcshxy.ap-northeast-2.es.amazonaws.com"```
```

## Create an EKS Cluster (if you don't have one yet)

```bash
# Use the eksctl to create a new EKS cluster on existing VPC
eksctl create cluster -f ./cluster.yaml

# Name of EKS cluster
CLUSTER_NAME=$(cat eksctl.yaml | yq .metadata.name)

# Confirm the IAM OIDC identity provider for your cluster has been enabled
aws eks describe-cluster --name $CLUSTER_NAME --query "cluster.identity.oidc.issuer" --output text
```
If you can't retrieve your EKS cluster's IAM OIDC identity provider, please see https://docs.aws.amazon.com/eks/latest/userguide/enable-iam-roles-for-service-accounts.html document to enable it properly

## Create an IAM policy and assign it to the service account:

```bash
# Substitute the values of environment variables into the fluent-bit-policy.json file, and output the result to a new file fluent-bit-policy_edited.json
cat ./fluent-bit-policy.json| envsubst > ./fluent-bit-policy_edited.json

# Create IAM policy
aws iam create-policy   \
  --policy-name fluent-bit-policy \
  --policy-document file://fluent-bit-policy_edited.json

# Bind IAM role to the Kubernetes SA
eksctl create iamserviceaccount --name fluent-bit --namespace kube-system --cluster $CLUSTER_NAME --role-name fluent-bit-role \
    --attach-policy-arn arn:aws:iam::$ACCOUNT_ID:policy/fluent-bit-policy --approve

# Confirm that the IAM role's trust policy is configured correctly.
aws iam get-role --role-name fluent-bit-role --query Role.AssumeRolePolicyDocument

export FLUENTBIT_ROLE=arn:aws:iam::$ACCOUNT_ID:role/fluent-bit-role

# Update OpenSearch roles mapping
curl -sS -u "${ES_DOMAIN_USER}:${ES_DOMAIN_PASSWORD}" \
    -X PATCH \
    "https://${ES_ENDPOINT}/_opendistro/_security/api/rolesmapping/all_access?pretty" \
    -H 'Content-Type: application/json' \
    -d '[
            {
                "op": "add", "path": "/backend_roles", "value": ["'${FLUENTBIT_ROLE}'"]
            }
        ]'

```

## Install Fluent Bit on EKS cluster
```bash
# https://github.com/aws/eks-charts/tree/master/stable/aws-for-fluent-bit

# Add aws-for-fluent-bit helm repo
helm repo add eks https://aws.github.io/eks-charts

# Install Fluent Bit Daemonset in kube-system namespace
helm upgrade --install fluent-bit eks/aws-for-fluent-bit \
  --namespace kube-system --set cloudWatchLogs.enabled=false \
  --set serviceAccount.create=false --set serviceAccount.name=fluent-bit \
  --set opensearch.enabled=true --set opensearch.awsRegion=ap-northeast-2 \
  --set opensearch.host=search-cloudacode-es-xxx.ap-northeast-2.es.amazonaws.com \
  --set opensearch.index=aws-fluent-bit

curl -sS -u "${ES_DOMAIN_USER}:${ES_DOMAIN_PASSWORD}" \
    -XGET "https://${ES_ENDPOINT}/aws-fluent-bit?pretty" \
    -H 'Content-Type: application/json'

```
To search the index and view data in AWS OpenSearch
Navigate to OpenSearch Dashboard Home > Manage > Dashboard Management > Index patterns > Create index pattern
Define an index pattern named "aws-fluent-bit" > Click "Next" and configure settings > from dropdown select "@timestamp" >> click "Create index pattern" button

![create-index-pattern](./create-index-pattern.png)


## Deploy test nginx pod for generating logs

```bash
# Create a demo nginx pod
kubectl run nginx --image=nginx -n default

# Forwards traffic from port 8080 on your local machine to port 80 on the nginx pod
kubectl port-forward nginx -n default 8080:80 &

# Loop that makes 10 HTTP GET requests to the nginx
for i in {1..10}; do curl "http://127.0.0.1:8080/$i"; echo; sleep 2; done
```

![log-dashboard](./opensearch-discover-dashboard.png)

## Reference

```bash
# How to Configure Logging AWS EKS on Fargate to AWS OpenSearch
https://github.com/aws-samples/aws-eks-se-samples/blob/main/examples/kubernetes/how-to-logging-eks-fargate-opensearch/readme.md

# Why can't I use an IAM role for the service account in my Amazon EKS pod?
https://repost.aws/knowledge-center/eks-pods-iam-role-service-accounts

# Fluent-bit helm chart
https://github.com/aws/eks-charts/tree/master/stable/aws-for-fluent-bit
```
