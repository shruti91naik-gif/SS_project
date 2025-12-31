{
   "Version": "2012-10-17",
   "Statement": [
       {
           "Sid": "RDSConnect",
           "Effect": "Allow",
           "Action": "rds-db:connect",
           "Resource": ${jsonencode(RESOURCES)}
       },
       {
           "Sid": "RDSFetchMetadata",
           "Effect": "Allow",
           "Action": [
               "rds:DescribeDBInstances"
           ],
           "Resource": "*"
       }
   ]
}
