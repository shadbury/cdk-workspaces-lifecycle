import boto3


class S3:
    def __init__(self, region_name):
        self.region_name = region_name
        self.client = self.get_s3_client()

    def get_s3_client(self):
        """
        Connect to AWS S3
        :return: S3 client
        """
        return boto3.client("s3", region_name=self.region_name)

    def download_file(self, bucket, key, local_file):
        """
        Download file from S3
        :param bucket: S3 bucket
        :param key: S3 key
        :param local_file: local file
        :return:
        """
        self.client.download_file(bucket, key, local_file)
    
    def put_object(self, file, bucket, key):
        """
        Upload file to S3
        :param file: file to upload
        :param bucket: S3 bucket
        :param key: S3 key
        :return:
        """
        self.client.put_object(Body=file, Bucket=bucket, Key=key)
