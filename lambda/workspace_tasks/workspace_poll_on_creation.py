from aws.workspaces import Workspaces
from util.exceptions import WorkspaceStillInPendingException


def poll(
    region,
    event,
    proxy
):

    if proxy:
        workspaces = Workspaces(region, proxy)
    else:
        workspaces = Workspaces(region)

    workspace_details = event.get("created_workspaces_details", [])
    if workspace_details:
        workspace_ids = [workspace["workspace_id"]
                         for workspace in workspace_details]
        workspaces = workspaces.get_workspaces(workspace_ids)
        while True:
            for workspace in workspaces.get("Workspaces", []):
                if workspace["State"] == "PENDING":
                    raise WorkspaceStillInPendingException(
                        workspace["WorkspaceId"])
            if "NextToken" not in workspaces or not workspaces["NextToken"]:
                break
            workspaces = workspaces.get_workspaces(
                workspace_ids, NextToken=workspaces["NextToken"]
            )

    return event
