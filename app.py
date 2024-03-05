#!/usr/bin/env python3
import os
import aws_cdk as cdk
from cdk_workspaces_functions.cdk_workspaces_functions_stack import CdkWorkspacesFunctionsStack


app = cdk.App()
CdkWorkspacesFunctionsStack(app, "CdkWorkspacesFunctionsStack",)
app.synth()
