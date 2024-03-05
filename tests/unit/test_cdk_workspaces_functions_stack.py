import aws_cdk as core
import aws_cdk.assertions as assertions

from cdk_workspaces_functions.cdk_workspaces_functions_stack import CdkWorkspacesFunctionsStack

# example tests. To run these tests, uncomment this file along with the example
# resource in cdk_workspaces_functions/cdk_workspaces_functions_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = CdkWorkspacesFunctionsStack(app, "cdk-workspaces-functions")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
