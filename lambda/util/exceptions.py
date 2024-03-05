

class WorkspaceStillInPendingException(Exception):
    def __init__(self, workspace_id):
        self.workspace_id = workspace_id

    def __str__(self):
        message = "The workspace {} is still in PENDING status".format(
            self.workspace_id
        )
        return message