from util.logger import get_logger
import os
import csv
from datetime import datetime
from util.defaults import LOCAL_TIMEZONE

logger = get_logger()

def get_workspaces_connection(client, workspaces, workspaces_period):
    workspaces_ids = []
    workspaces_connections = {}
    slice_range = 20

    for workspace in workspaces:
        if workspaces_period.get(workspace.get("ComputerName")):
            workspaces_ids.append(workspace.get("WorkspaceId"))

    while workspaces_ids:
        logger.debug(
            "workspaces_ids: [{}] {}".format(len(workspaces_ids), workspaces_ids)
        )
        batch = workspaces_ids[0:slice_range]
        workspaces_ids = workspaces_ids[slice_range:]
        response = client.describe_workspaces_connection_status(WorkspaceIds=batch)
        logger.debug("response: {}".format(response))

        for con in response["WorkspacesConnectionStatus"]:
            workspaces_connections[con.get("WorkspaceId")] = con.get(
                "LastKnownUserConnectionTimestamp", None
            )

    logger.debug("workspaces_connections: {}".format(workspaces_connections))
    return workspaces_connections


def create_csv_report(report_name, header, rows):
    """
    Creates a new csv file and ititializes it with a header
    :param report_name: name of the report
    :param header: list of values
    :return: csv file path
    """
    today = datetime.utcnow().astimezone(LOCAL_TIMEZONE)
    report_date = today.strftime("%Y-%m-%d")
    report_file_name = "/tmp/{reportdate}-{reportname}.csv".format(
        reportdate=report_date, reportname=report_name
    )
    delete_file(report_file_name)

    with open(report_file_name, "a") as csvfile:
        # Match headers with dict (rows) keys to write the csv file in order
        csv_report = csv.DictWriter(
            csvfile,
            fieldnames=header,
            delimiter=",",
            quotechar="|",
            quoting=csv.QUOTE_MINIMAL,
            extrasaction="ignore",
        )
        csv_report.writeheader()
        csv_report.writerows(rows)
    return report_file_name

def delete_file(file_name):
    """
    Delete a file if it is already present
    :param file_name: file path
    :return:
    """
    try:
        os.remove(file_name)
    except OSError:
        pass