import boto3
import botocore.endpoint
from botocore.exceptions import ClientError
import backoff
from util.logger import get_logger
from util.defaults import MAX_TRIES, LOCAL_TIMEZONE
from util.common import fatal_code, convert_tag_list_to_map

logger = get_logger()


class Workspaces:
    '''
    Workspaces class to interact with AWS Workspaces
    '''

    def __init__(self, region_name):
        self.region_name = region_name
        self.client = self.get_workspaces_client()

    def __init__(self, region_name, proxy):
        self.region_name = region_name
        self.session = boto3.Session(region_name=self.region_name)
        self.client = self.session.client("workspaces")
        botocore.endpoint.EndpointCreator._get_proxies = self._get_proxies(
            proxy)

    def _get_proxies(self, proxy):
        return {"http": proxy, "https": proxy}

    def get_workspaces_client(self):
        """
        Connect to AWS APIs
        :return: workspaces client
        """
        return boto3.client("workspaces")
                
    @backoff.on_exception(backoff.expo, ClientError, max_tries=MAX_TRIES, giveup=fatal_code)
    def modify_workspace_properties(self, **args):
        try:
            logger.debug("calling the modify_workspace_properties API")
            return self.client.modify_workspace_properties(**args)
        except ClientError as e:
            return e.response["Error"]["Code"]
    
    @backoff.on_exception(backoff.expo, ClientError, max_tries=MAX_TRIES, giveup=fatal_code)
    def create_workspaces(self, **args):
        logger.debug("calling the create_workspaces API")
        return self.client.create_workspaces(**args)

    def get_all_workspaces(self):
        """
        Returns existing workspaces details
        :param client: a boto3 workspaces client
        :return flat_list:  list of dictionaries with workspaces details
        """
        all_workspaces = []

        paginator = self.client.get_paginator("describe_workspaces")
        pages = paginator.paginate()

        for page in pages:
            if page["ResponseMetadata"]["HTTPStatusCode"] != 200:
                raise Exception("Non-200 Workspaces Error Code")
            else:
                all_workspaces.append(page.get("Workspaces", None))

        flat_list = [item for sublist in all_workspaces for item in sublist]

        return flat_list
    
    def get_workspaces(self, workspace_ids, next_token=None):
        """
        Returns the details of a workspace
        :param workspace_id: The ID of the workspace
        :return: The details of the workspace
        """
        return self.client.describe_workspaces(WorkspaceIds=[workspace_ids], NextToken=next_token)
    

    def search_directory_registration_code(self, directory_ids):
        '''
        Returns registration code for a given directory
        '''
        registration_code_map = {}
        directories = self.describe_workspace_directories(
            DirectoryIds=directory_ids)
        logger.info(directories)
        while True:
            for directory in directories.get("Directories", []):
                directory_id = directory["DirectoryId"]
                registration_code = directory["RegistrationCode"]
                registration_code_map[directory_id] = registration_code
            if "NextToken" not in directories or not directories["NextToken"]:
                break
            directories = self.describe_workspace_directories(
                self, DirectoryIds=directory_ids, NextToken=directories["NextToken"]
            )
        return registration_code_map

    def get_workspaces_directories(self):
        '''
        Returns existing workspaces directories
        '''
        workspace_user_directories = {}
        logger.info("searching workspaces")
        workspaces = self.get_all_workspaces()

        for workspace in workspaces["Workspaces"]:
            logger.info(workspace)
            username = workspace["UserName"]
            directory_id = workspace["DirectoryId"]
            if directory_id not in workspace_user_directories:
                workspace_user_directories[directory_id] = []
            workspace_user_directories[directory_id].append(username)

        return workspace_user_directories
    
    def terminate_workspaces(self, workspace_ids):
        '''
        Terminate all workspaces in workspace_ids
        '''
        return self.client.terminate_workspaces(TerminateWorkspaceRequests=[{"WorkspaceId": workspace_id} for workspace_id in workspace_ids])
        

    def get_workspace_details(self, details=["WorkspaceId", "ComputerName", "UserName", "DirectoryId", "Tags"]):
        """
        Returns existing workspaces details
        :param client: a boto3 workspaces client
        :return flat_list:  list of workspaces with relevant details
        """

        all_workspaces = []
        res_workspaces = self.get_all_workspaces()
        while True:
            for workspace in res_workspaces["Workspaces"]:
                res_tag = self.client.describe_tags(ResourceId=workspace["WorkspaceId"])
                
                if details and all(key in workspace for key in details):
                    all_workspaces.append(
                        {
                            "WorkspaceId": workspace["WorkspaceId"],
                            "ComputerName": workspace.get("ComputerName", "Unknown"),
                            "UserName": workspace["UserName"],
                            "DirectoryId": workspace["DirectoryId"],
                            "RunningMode": workspace["WorkspaceProperties"]["RunningMode"],
                            "ComputeTypeName": workspace["WorkspaceProperties"][
                                "ComputeTypeName"
                            ],
                            "Tags": convert_tag_list_to_map(res_tag.get("TagList", [])),
                        }
                    )
            if "NextToken" not in res_workspaces:
                break
            res_workspaces = self.client.describe_workspaces(NextToken=res_workspaces["NextToken"])
        return all_workspaces
    
    def create_workspace_tags(self, workspace_id, tags):
        '''
        Creates tags for a workspace
        
        :param workspace_id: The ID of the workspace
        :param tags: A list of tags to associate with the workspace
        '''
        return self.client.create_tags(ResourceId=workspace_id, Tags=tags)
    
    
    def delete_workspace_tags(self, workspace_id, tags):
        """
        Deletes all tags associated with a workspace
        :param workspace_id: The ID of the workspace
        """
        return self.client.delete_tags(ResourceId=workspace_id, Tags=tags)
    
    def _get_workspaces_last_connection(self, workspaces_ids):
        global _workspaces_last_connection
        workspaces_ids_to_search = [
            w for w in workspaces_ids if w not in _workspaces_last_connection
        ]
        slice_range = 20
        while workspaces_ids_to_search:
            logger.debug(
                "workspaces_ids: [{}] {}".format(
                    len(workspaces_ids_to_search), workspaces_ids_to_search
                )
            )
            batch = workspaces_ids_to_search[0:slice_range]
            workspaces_ids_to_search = workspaces_ids_to_search[slice_range:]
            response = self.client.describe_workspaces_connection_status(WorkspaceIds=batch)

            for con in response["WorkspacesConnectionStatus"]:
                t = con.get("LastKnownUserConnectionTimestamp", "Unknown")
                if t != "Unknown":
                    t = t.astimezone(LOCAL_TIMEZONE)
                _workspaces_last_connection[con["WorkspaceId"]] = t
        return _workspaces_last_connection
