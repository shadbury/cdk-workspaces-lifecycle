import boto3
from util.logger import get_logger
from util.defaults import MAX_WORKSPACES_PER_AD_CONNECTOR

logger = get_logger()


class DirectoryManager:
    def __init__(self, workspace_user_directories, event_ads):
        self.ds_client = boto3.client("ds")
        self.workspace_user_directories = workspace_user_directories
        self.ad_group_directories = {}
        self.directory_sizes = {}
        for event_ad in event_ads:
            ad_group_name = event_ad["group_name"]
            self.ad_group_directories[ad_group_name] = []
            for ad_id in event_ad["directory_ids"]:
                self.ad_group_directories[ad_group_name].append(ad_id)
                self.directory_sizes[ad_id] = event_ad["directory_ids"][ad_id]

    def get_directory_id(self, ad_group_name, user_name):
        logger.debug("AD - requested directory for: {}".format(ad_group_name))
        for directory_id in self.ad_group_directories.get(ad_group_name, []):
            max_workspaces = MAX_WORKSPACES_PER_AD_CONNECTOR[
                self.directory_sizes[directory_id]
            ]
            if (
                len(self.workspace_user_directories.get(directory_id, []))
                < max_workspaces
            ):
                if directory_id not in self.workspace_user_directories:
                    self.workspace_user_directories[directory_id] = []
                self.workspace_user_directories[directory_id].append(user_name)
                logger.debug(
                    "AD - return {} for: {}".format(directory_id,
                                                    ad_group_name)
                )
                return directory_id
        raise Exception(
            "All the AD connectors associated to '{}' are full and no further workspaces can be created. "
            "Please create a new AD connector and associated it to the AD group above".format(
                ad_group_name
            )
        )
