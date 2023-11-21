# IAAS service connectors

"""
GCP
"""
GCP_TOKEN_EP = 'https://accounts.google.com/o/oauth2/token'
GCP_SCOPE = 'https://www.googleapis.com/auth/cloud-platform'
GCP_API = {
    'project':'https://cloudresourcemanager.googleapis.com/v1/projects',
    'compute':'https://compute.googleapis.com/compute/v1/projects',
    'container':'https://container.googleapis.com/v1/projects',
    'storage':'https://storage.googleapis.com/storage/v1/b',
    'iam':'https://iam.googleapis.com/v1',
}
GCP_JWT = {
    'grant_type':'urn:ietf:params:oauth:grant-type:jwt-bearer',
    'algorithm':'RS256',
    'expire':3600
}
GCP_REGIONS = {
    'asia-east1':['a','b','c'],
    'asia-east2':['a','b','c'],
    'asia-northeast1':['a','b','c'],
    'asia-northeast2':['a','b','c'],
    'asia-south1':['a','b','c'],
    'asia-southeast1':['a','b','c'],
    'australia-southeast1':['a','b','c'],
    'europe-north1':['a','b','c'],
    'europe-west1':['b','c','d'],
    'europe-west2':['a','b','c'],
    'europe-west3':['a','b','c'],
    'europe-west4':['a','b','c'],
    'europe-west6':['a','b','c'],
    'northamerica-northeast1':['a','b','c'],
    'southamerica-east1':['a','b','c'],
    'us-central1':['a','b','c','f'],
    'us-east1':['b','c','d'],
    'us-east4':['a','b','c'],
    'us-west1':['a','b','c'],
    'us-west2':['a','b','c'],
}
"""
Azure
"""
AZURE_TOKEN_EP = 'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
AZURE_API_EP = 'https://management.azure.com'
AZURE_API = {
    'subscription':{'path': '/subscriptions', 'version': '2020-01-01'},
    'resource':{'path': '/resources', 'version': '2021-04-01'},
    'assessment':{'path': '/providers/Microsoft.Security/assessments', 'version': '2020-01-01'},
    'virtualmachine':{'path': '/providers/Microsoft.Compute/virtualMachines', 'version': '2021-03-01'},
    'snapshot':{'path': '/providers/Microsoft.Compute/virtualMachines/snapshots', 'version': '2020-12-01'},
    'disk':{'path': '/providers/Microsoft.Compute/virtualMachines/disks', 'version': '2020-12-01'},
    'firewall':{'path': '/providers/Microsoft.Network/azureFirewalls', 'version': '2021-02-01'},
    'vnet':{'path': '/providers/Microsoft.Network/virtualNetworks', 'version': '2021-02-01'},
    'publicip':{'path': '/providers/Microsoft.Network/publicIPAddresses', 'version': '2021-02-01'},
    'vwan':{'path': '/providers/Microsoft.Network/virtualWans', 'version': '2021-02-01'},
    'vhub':{'path': '/providers/Microsoft.Network/virtualHubs', 'version': '2021-02-01'},
    'vgateway':{'path': '/providers/Microsoft.Network/vpnGateways', 'version': '2021-02-01'},
    'storageaccount':{'path': '/providers/Microsoft.Storage/storageAccounts', 'version': '2021-04-01'},
    'sql':{'path': '/providers/Microsoft.Sql/servers', 'version': '2021-02-01-preview'}
}
"""
AWS
"""
AWS_API = {
    'report':{'service': 'iam', 'method': 'get_credential_report', 'container': 'Content', 'paginate': False},
    'bucket':{'service': 's3', 'method': 'list_buckets', 'container': 'Buckets', 'paginate': False},
    'bucketacl':{'service': 's3', 'method': 'get_bucket_acl', 'paginate': False},
    'vpc':{'service': 'ec2', 'method': 'describe_vpcs', 'container': 'Vpcs'},
    'securitygroup':{'service': 'ec2', 'method': 'describe_security_groups', 'container': 'SecurityGroups'},
    'subnet':{'service': 'ec2', 'method': 'describe_subnets', 'container': 'Subnets'},
    'instance':{'service': 'ec2', 'method': 'describe_instances', 'container': 'Reservations'},
    'volume':{'service': 'ec2', 'method': 'describe_volumes', 'container': 'Volumes'},
    'snapshot':{'service': 'ec2', 'method': 'describe_snapshots', 'container': 'Snapshots'},
    'cluster':{'service': 'rds', 'method': 'describe_db_clusters', 'container': 'DBClusters'},
    'subnetgroup':{'service': 'rds', 'method': 'describe_db_subnet_groups', 'container': 'DBSubnetGroups'},
    'dbsnapshot':{'service': 'rds', 'method': 'describe_db_snapshots', 'container': 'DBSnapshots'},
    'lightsail':{'service': 'lightsail', 'method': 'get_instances', 'container': 'instances'},
    'elb':{'service': 'elb', 'method': 'describe_load_balancers', 'container': 'LoadBalancerDescriptions'}
}