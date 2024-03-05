import boto3
import botocore.endpoint


class SSM:
    '''
    SSM class to interact with AWS SSM
    '''

    def __init__(self, region_name):
        self.region_name = region_name
        self.session = boto3.Session(region_name=self.region_name)
        self.ssm = self.session.client("ssm")

    def __init__(self, region_name, proxy):
        self.region_name = region_name
        self.session = boto3.Session(region_name=self.region_name)
        self.ssm = self.session.client("ssm")
        botocore.endpoint.EndpointCreator._get_proxies = self._get_proxies(
            self, proxy)

    def _get_proxies(self, url, proxy):
        return {"http": proxy, "https": proxy}

    def get_parameter(self, name, with_decryption):
        """
        Get SSM parameter
        :param name: parameter name
        :param with_decryption: with decryption
        :return: parameter
        """
        return self.ssm.get_parameter(Name=name, WithDecryption=with_decryption)
