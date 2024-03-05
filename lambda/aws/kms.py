from util.logger import get_logger
from util.common import fatal_code
from util.defaults import MAX_WORKSPACES_PER_KMS_KEY
import re
import boto3
import backoff
from botocore.exceptions import ClientError
from util.defaults import MAX_TRIES

logger = get_logger()

@backoff.on_exception(backoff.expo, ClientError, max_tries=MAX_TRIES, giveup=fatal_code)
def list_aliases(kms_client, **args):
    logger.debug("calling the list_aliases API")
    return kms_client.list_aliases(**args)


@backoff.on_exception(backoff.expo, ClientError, max_tries=MAX_TRIES, giveup=fatal_code)
def list_grants(kms_client, **args):
    logger.debug("calling the list_grants API")
    return kms_client.list_grants(**args)


@backoff.on_exception(backoff.expo, ClientError, max_tries=MAX_TRIES, giveup=fatal_code)
def create_key(kms_client, **args):
    logger.debug("calling the create_key API")
    return kms_client.create_key(**args)


@backoff.on_exception(backoff.expo, ClientError, max_tries=MAX_TRIES, giveup=fatal_code)
def create_alias(kms_client, **args):
    logger.debug("calling the create_alias API")
    return kms_client.create_alias(**args)


class KmsManager:
    def __init__(self, prefixes):
        self.key_pattern = re.compile(r"[a-zA-Z0-9:_-]+")
        self.kms_key_info = {}
        for prefix in prefixes:
            clean_prefix = "".join(re.findall(self.key_pattern, prefix))
            self.kms_key_info[clean_prefix] = []

        self.w_client = boto3.client("kms")
        res = list_aliases(self.w_client)
        while True:
            for alias in res.get("Aliases", []):
                if alias["AliasName"].startswith("alias/workspace/"):
                    index = alias["AliasName"].split("/")[2]
                    if index in self.kms_key_info:
                        self.kms_key_info[index].append(
                            {"alias": alias["AliasName"],
                                "id": alias["TargetKeyId"]}
                        )
            next_marker = res.get("NextMarker")
            if not next_marker:
                break
            res = list_aliases(self.w_client, Marker=next_marker)

        for prefix in self.kms_key_info:
            kms_keys = self.kms_key_info[prefix]
            for kms_key in kms_keys:
                kms_key["availability"] = self._get_key_availability(
                    kms_key["id"])
        logger.debug("KMS key object: {}".format(self.kms_key_info))
        return

    def _get_key_availability(self, key_id):
        availability = MAX_WORKSPACES_PER_KMS_KEY
        res = list_grants(self.w_client, KeyId=key_id)
        while True:
            availability = availability - len(res.get("Grants", []))
            next_marker = res.get("NextMarker")
            if not next_marker:
                break
            res = list_grants(self.w_client, KeyId=key_id, Marker=next_marker)
        if availability < 0:
            availability = 0
        return availability

    def get_key_id(self, index):
        logger.debug("KMS key object: {}".format(self.kms_key_info))
        logger.debug("KMS - requested key for: {}".format(index))
        clean_index = "".join(re.findall(self.key_pattern, index))
        keys = self.kms_key_info[clean_index]
        for key in keys:
            if key["availability"] > 0:
                key["availability"] = key["availability"] - 1
                logger.debug("KMS key object: {}".format(self.kms_key_info))
                return key["id"]
        logger.debug(
            "KMS - no available key for: {}. Creating a new one".format(
                clean_index)
        )
        existing_key_aliases = [key["alias"] for key in keys]
        n = 1
        while True:
            new_key_alias = "alias/workspace/{}/{}".format(clean_index, n)
            if new_key_alias not in existing_key_aliases:
                break
            n += 1

        res = create_key(
            self.w_client, Description="Key used by workspaces - {}".format(
                index)
        )
        new_key_id = res["KeyMetadata"]["KeyId"]
        create_alias(self.w_client, AliasName=new_key_alias,
                     TargetKeyId=new_key_id)
        self.kms_key_info[clean_index].append(
            {
                "alias": new_key_alias,
                "id": new_key_id,
                "availability": (MAX_WORKSPACES_PER_KMS_KEY - 1),
            }
        )
        logger.debug("KMS key object: {}".format(self.kms_key_info))
        return new_key_id
