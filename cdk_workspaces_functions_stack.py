from aws_cdk import (
    Stack,
    aws_lambda as lambda_
)
from os import path
from constructs import Construct


class CdkWorkspacesFunctionsStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        functions = {
            "Name": "WorkspaceUserSync",
            "Name": "WorkspaceTerminate",
            "Name": "WorkspaceCreateReport",
            "Name": "WorkspaceSendReport",
            "Name": "WorkspaceADCleanup",
            "Name": "WorkspacePollOnCreation",
            "Name": "WorkspaceNotifyUser",
            "Name": "WorkspaceTaskEnd"
        }

        master_lambda = lambda_.Function(self, "MyLambda",
                                         code=lambda_.Code.from_asset(
                                             path.join("lambda", "workspaces_manager")),
                                         handler="index.main",
                                         runtime=lambda_.Runtime.PYTHON_3_11
                                         )
