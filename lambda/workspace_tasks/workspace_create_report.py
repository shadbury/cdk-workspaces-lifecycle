import os
import csv
import ast
from datetime import datetime, timedelta
from pytz import timezone
from dateutil.relativedelta import relativedelta
from dateutil.parser import parse
from dateutil.tz import gettz
from aws.workspaces import Workspaces


_all_workspaces = []
_all_workspaces_first_run = True


def _datetime_to_string(input):
    try:
        return input.strftime("%Y-%m-%d %H:%M:%S %Z")
    except Exception as e:
        logger.debug("Error pasing date: {}. Reason: {}".format(input, str(e)))
        return "Unknown"


def fill_workspaces_with_creation_date(ldap, workspaces, active_directories):
    ldap_computers = get_ldap_computers(active_directories)
    for workspace in workspaces:
        if (
            workspace["ComputerName"] in ldap_computers
            and "CreationDatetime" not in workspace
        ):
            workspace["CreationDatetime"] = ldap_computers[workspace["ComputerName"]][
                "whenCreated"
            ]
            workspace["CreationTime"] = _datetime_to_string(
                workspace["CreationDatetime"]
            )


_workspaces_last_connection = {}


def fill_workspaces_with_last_connection(client, workspaces, add_comment=True):
    logger.info("Getting AWS WorkSpaces connection status")
    workspaces_ids = [w["WorkspaceId"] for w in workspaces]
    workspaces_last_connection = _get_workspaces_last_connection(client, workspaces_ids)
    for w in workspaces:
        last_connection = workspaces_last_connection.get(w["WorkspaceId"], "Unknown")
        w["LastKnownUserConnectionDatetime"] = last_connection
        if last_connection == "Unknown":
            w["LastKnownUserConnectionTime"] = "Unknown"
            if add_comment:
                w["Comments"] = "Never connected"
            w["DaysSinceLastConnection"] = -1
        else:
            last_connection.replace(microsecond=0)
            w["LastKnownUserConnectionTime"] = _datetime_to_string(last_connection)
            days = days_since_last_connection(last_connection)
            w["DaysSinceLastConnection"] = days
            if add_comment:
                if days == 1:
                    w["Comments"] = "Last connection was 1 day ago"
                else:
                    w["Comments"] = "Last connection was {} days ago".format(days)
    return


def _get_workspaces_ou_list(active_directories):
    ou_list = [
        active_directory["workspaces_organizational_unit"]
        for active_directory in active_directories
    ]
    ou_list = list(dict.fromkeys(ou_list))
    return ou_list



def days_since_last_connection(last_connection):
    now = datetime.utcnow().astimezone(LOCAL_TIMEZONE)
    if last_connection:
        logger.debug(now)
        logger.debug(last_connection)
        delta = (now - last_connection).days
        return delta
    else:
        return -1


def days_until_termination(date):
    today = (
        datetime.utcnow().astimezone(LOCAL_TIMEZONE).replace(hour=0, minute=0, second=0)
    )
    logger.debug(today)
    logger.debug(date)
    delta = (date - today).days

    if (date - today).seconds != 0:
        delta += 1
    return delta


def get_previous_month():
    """
    Returns the last month as integer
    :return: Returns the last month as date object
    """
    last_month = datetime.now() - relativedelta(months=1)

    return last_month


def convert_ldap_timestamp(timestamp):
    """
    Converts a LDAP timestamp to a datetime
    :param timestamp: the LDAP timestamp
    :return A datetime
    """
    try:
        timestamp = int(timestamp)
        converted_timestamp = datetime.fromtimestamp(timestamp).astimezone(
            LOCAL_TIMEZONE
        )
    except ValueError:
        converted_timestamp = datetime.strptime(
            timestamp.split(".")[0], "%Y%m%d%H%M%S"
        ).astimezone(LOCAL_TIMEZONE)

    return converted_timestamp


def csv_file_generate(report_name, header):
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
    csv_add_row(report_file_name, header)

    return report_file_name


def csv_add_row(csv_file, row):
    """
    Adds a new line to a csv file
    :param csv_file: file path
    :param row: list of values
    :return: None
    """
    with open(csv_file, "a") as csvfile:
        csv_report = csv.writer(
            csvfile, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL
        )
        csv_report.writerow(row)
    return None


_ldap_computers = {}
_ldap_computers_first_run = True


def get_ldap_computers(ldap, active_directories):
    global _ldap_computers_first_run
    global _ldap_computers
    if not _ldap_computers_first_run:
        return _ldap_computers
    computers_search_attribute = [
        "name",
        "displayName",
        "sAMAccountName",
        "distinguishedName",
        "whenCreated",
    ]
    workspaces_search_filter = "(objectClass=computer)"
    for workspaces_ou in _get_workspaces_ou_list(active_directories):
        logger.info(
            "Searching for computer objects in the following OU: '{}'".format(
                workspaces_ou
            )
        )
        ldap_computers_in_ou = ldap.ldap_search(
            workspaces_ou,
            workspaces_search_filter,
            computers_search_attribute,
        )
        logger.info("Decoding LDAP search response")
        for elem in ldap_computers_in_ou:
            for key, value in elem.items():
                decoded_value = "".join(decode(value))
                if key == "whenCreated":
                    decoded_value = convert_ldap_timestamp(decoded_value)
                elem[key] = decoded_value
            _ldap_computers[elem["name"]] = elem
    logger.debug("ldap_computers: {}".format(_ldap_computers))
    _ldap_computers_first_run = False
    return _ldap_computers


_ldap_users = {}


def get_ldap_users(ldap_con, users_base_dn, ldap_users_ids):
    global _ldap_users
    users_search_attribute = ["sAMAccountName", "name", "givenName", "sn"]
    ldap_users_ids_to_search = []
    for user_id in ldap_users_ids:
        if user_id not in _ldap_users:
            ldap_users_ids_to_search.append("(sAMAccountName={id})".format(id=user_id))
    # Find any user who has sAMAccountName=u111 OR sAMAccountName=u112 OR sAMAccountName=u113 OR ...
    users_search_filter = "(&(objectClass=User)(objectCategory=Person)(|{user_ids}))".format(
        user_ids="".join(ldap_users_ids_to_search)
    )
    ldap_users = ldap_search(
        ldap_con, users_base_dn, users_search_filter, users_search_attribute
    )

    logger.info("Decoding LDAP search response")
    for user in ldap_users:
        if user is None:  # Indicates no results
            continue
        user_cn = decode(user)
        account_name = decode(user["sAMAccountName"][0])
        user_full_name = decode(user["name"][0]) if user["name"] else "None"
        user_given_name = decode(user["givenName"][0]) if user["givenName"] else "None"
        user_surname = decode(user["sn"][0]) if user["sn"] else "None"
        # Generate dictionary  by {user_id: {full_name: user_name, given_name: givenName, surname: sn .....}}
        _ldap_users[user["sAMAccountName"]] = {
            "full_name": user_full_name.replace(",", " "),
            "given_name": user_given_name.replace(",", " "),
            "surname": user_surname.replace(",", " "),
            "user_id": account_name,
        }
    return _ldap_users


def filter_workspaces_created_after_X_day(workspaces, today, days):
    if days > 0:
        logger.info("Filtering workspaces created after {} days".format(days))
        day_0 = today - timedelta(days=days)
        logger.info("Day 0: {}".format(day_0))
        filtered_workspaces = [w for w in workspaces if w["CreationDatetime"] > day_0]
        logger.info("Filtered workspaces ({}):".format(len(filtered_workspaces)))
        logger.info(filtered_workspaces)
        return filtered_workspaces
    else:
        return workspaces


def _get_directory_id_group_name_map(active_directories):
    directory_map = {}
    for active_directory in active_directories:
        for directory_id in active_directory["directory_ids"]:
            directory_map[directory_id] = active_directory["group_name"]
    return directory_map


def fill_workspaces_with_user_info(
    ldap_con, users_base_dn, workspaces, active_directories
):
    directory_id_group_name_map = _get_directory_id_group_name_map(active_directories)
    logger.info("Searching for Workspace users")
    aws_workspaces_user_ids = [w["UserName"] for w in workspaces]
    ldap_users = get_ldap_users(ldap_con, users_base_dn, aws_workspaces_user_ids)
    for w in workspaces:
        w["AdUserFullName"] = ldap_users.get(w["UserName"], {}).get("full_name", "None")
        w["AdUserGivenName"] = ldap_users.get(w["UserName"], {}).get(
            "given_name", "None"
        )
        w["AdUserSurname"] = ldap_users.get(w["UserName"], {}).get("surname", "None")
        w["AdUserGroupName"] = directory_id_group_name_map.get(
            w["DirectoryId"], "Unknown"
        )


def convert_tag_list_to_map(tag_list):
    tag_map = {}
    for tag_obj in tag_list:
        tag_map[tag_obj["Key"]] = tag_obj["Value"]
    return tag_map


def fill_workspaces_with_deletion_tag(client, workspaces, add_comment=True):
    for workspace in workspaces:
        if "TerminationDate" not in workspace:
            res_tag = aws_function(
                client.describe_tags, ResourceId=workspace["WorkspaceId"]
            )
            termination_date_str = convert_tag_list_to_map(
                res_tag.get("TagList", [])
            ).get("TerminationDate", "")
            if not termination_date_str:
                workspace["TerminationDate"] = ""
                continue
            try:
                termination_date = parse(
                    termination_date_str, tzinfos=TZ_INFOS
                ).astimezone(LOCAL_TIMEZONE)
            except Exception as e:
                logger.error(
                    "Error parsing the date [{}]: {}".format(
                        termination_date_str, str(e)
                    )
                )
                workspace["TerminationDate"] = ""
                continue
            workspace["TerminationDate"] = termination_date_str
            workspace["DaysUntilTermination"] = days_until_termination(termination_date)
            if add_comment:
                if workspace["DaysUntilTermination"] == 1:
                    workspace["Comments"] = "Workspace to be deleted in 1 day"
                else:
                    workspace["Comments"] = "Workspace to be deleted in {} days".format(
                        workspace["DaysUntilTermination"]
                    )


def filter_workspaces_to_be_deleted_in_next_X_day(workspaces, days):
    filtered_workspaces = []
    logger.info("Filtering workspaces to be deleted in next {} days".format(days))
    logger.info("All workspaces: {}".format(workspaces))
    for workspace in workspaces:
        if (
            "DaysUntilTermination" in workspace
            and workspace["DaysUntilTermination"] <= days
        ):
            filtered_workspaces.append(workspace)
    logger.info("Filtered workspaces ({}):".format(len(filtered_workspaces)))
    logger.info(filtered_workspaces)
    return filtered_workspaces


def filter_workspaces_with_no_login_in_last_X_day(workspaces, days):
    filtered_workspaces = []
    logger.info("Filtering workspaces with no login in last {} days".format(days))
    logger.info("All workspaces: {}".format(workspaces))
    for workspace in workspaces:
        if "DaysSinceLastConnection" in workspace:
            if (
                workspace["DaysSinceLastConnection"] == -1
                or workspace["DaysSinceLastConnection"] >= days
            ):
                filtered_workspaces.append(workspace)
    logger.info("Filtered workspaces ({}):".format(len(filtered_workspaces)))
    logger.info(filtered_workspaces)
    return filtered_workspaces


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
        csv_report = csv.DictWriter(
            csvfile,
            fieldnames=header,
            delimiter=",",
            quotechar='"',
            quoting=csv.QUOTE_MINIMAL,
            extrasaction="ignore",
        )
        csv_report.writeheader()
        csv_report.writerows(rows)
    return report_file_name


def merge_csv_reports(report_name, headers, day, filenames):
    report_name = "/tmp/{reportdate}-{reportname}.csv".format(
        reportdate=day, reportname=report_name
    )
    with open(report_name, "w") as target:
        target.write(",".join(headers) + "\n")
        for filename in filenames:
            with open(filename, "r") as source:
                first_line = True
                for line in source:
                    if first_line:
                        first_line = False
                    else:
                        target.write(line)
    return report_name


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Global configuration                                                #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


logger = setup_logging()

proxy = os.environ.get("PROXY_URL")

if proxy is None:
    logger.info("Proxy is not defined....!")
else:
    logger.info("Proxy is defined: {proxy}".format(proxy=proxy))

    def _get_proxies(self, url):
        return {"http": proxy, "https": proxy}

    botocore.endpoint.EndpointCreator._get_proxies = _get_proxies

SSM_PASSWORD_PATH = os.environ.get("SSM_PASSWORD_PATH")
session = boto3.Session(region_name="ap-southeast-2")
ssm = session.client("ssm")
passwordecoded = ssm.get_parameter(Name=SSM_PASSWORD_PATH, WithDecryption=True)

max_retries = 20
retry_timeout = 3


def lambda_handler(event, context):
    # Initialize variables
    workspace_client = get_workspaces_client()
    s3_client = get_s3_client()
    bucket_report = os.getenv("BUCKET_REPORT")
    service_username = os.getenv("SERVICE_ACCOUNT")
    service_password = passwordecoded["Parameter"]["Value"]
    ldap_url = os.getenv("LDAP_URL")
    users_base_dn = os.getenv("DOMAIN_BASE_DN")
    active_directories = event["active_directory"]
    cmd_svc_acc = ast.literal_eval(
        os.getenv("CMD_SVC_ACCOUNTS") if os.getenv("CMD_SVC_ACCOUNTS") else "{}"
    )
    cmd_admin_users = ast.literal_eval(
        os.getenv("CMD_ADM_ACCOUNTS") if os.getenv("CMD_ADM_ACCOUNTS") else "{}"
    )
    cmd_users = {}
    cmd_users.update(**cmd_svc_acc, **cmd_admin_users)
    logger.info("Initializing LDAP connection")
    ldap_con = ldap_connection(ldap_url, service_username, service_password)

    today = datetime.utcnow().astimezone(LOCAL_TIMEZONE)
    reports = {}
    base_headers = [
        "UserName",
        "AdUserFullName",
        "AdUserGivenName",
        "AdUserSurname",
        "AdUserGroupName",
        "WorkspaceId",
        "DirectoryId",
        "ComputerName",
        "RunningMode",
        "ComputeTypeName",
        "CreationTime",
        "LastKnownUserConnectionTime",
    ]
    for key in event["report"]:
        logger.debug("event['report']['key']: {}".format(key))
        days = int(event["report"][key].get("days", "-1"))
        if key == "Workspaces provisioned in last X days":
            aws_workspaces = get_all_workspaces(workspace_client)
            fill_workspaces_with_creation_date(
                ldap_con, aws_workspaces, active_directories
            )
            filtered_workspaces = filter_workspaces_created_after_X_day(
                aws_workspaces, today, days
            )
            fill_workspaces_with_last_connection(workspace_client, filtered_workspaces)
            fill_workspaces_with_user_info(
                ldap_con, users_base_dn, filtered_workspaces, active_directories
            )

            logger.info("Generating CSV report")
            ws_report_headers = base_headers + ["Comments"]
            report_name = "workspaces-provisioned-in-last-{}-days".format(days)
            if days <= 0:
                report_name = "workspaces-provisioned"
            ws_report = create_csv_report(
                report_name, ws_report_headers, filtered_workspaces
            )
            logger.debug("ws_report: {}".format(ws_report))
            reports["Workspaces provisioned in last X days"] = ws_report
        elif key == "Workspaces to be deleted in X days":
            aws_workspaces = get_all_workspaces(workspace_client)
            fill_workspaces_with_creation_date(
                ldap_con, aws_workspaces, active_directories
            )
            fill_workspaces_with_deletion_tag(workspace_client, aws_workspaces)
            filtered_workspaces = filter_workspaces_to_be_deleted_in_next_X_day(
                aws_workspaces, days
            )
            fill_workspaces_with_last_connection(
                workspace_client, filtered_workspaces, add_comment=False
            )
            fill_workspaces_with_user_info(
                ldap_con, users_base_dn, filtered_workspaces, active_directories
            )

            logger.info("Generating CSV report")
            ws_report_headers = base_headers + ["TerminationDate", "Comments"]
            report_name = "workspaces-to-be-deleted-in-next-{}-days".format(days)
            if days < 0:
                report_name = "workspaces-to-be-deleted"
            ws_report = create_csv_report(
                report_name, ws_report_headers, filtered_workspaces
            )
            logger.debug("ws_report: {}".format(ws_report))
            reports["Workspaces to be deleted in X days"] = ws_report
        elif key == "Workspaces with no login in last X days":
            aws_workspaces = get_all_workspaces(workspace_client)
            fill_workspaces_with_creation_date(
                ldap_con, aws_workspaces, active_directories
            )
            fill_workspaces_with_last_connection(workspace_client, aws_workspaces)
            filtered_workspaces = filter_workspaces_with_no_login_in_last_X_day(
                aws_workspaces, days
            )
            fill_workspaces_with_user_info(
                ldap_con, users_base_dn, filtered_workspaces, active_directories
            )

            logger.info("Generating CSV report")
            ws_report_headers = base_headers + ["Comments"]
            report_name = "workspaces-with-no-login-in-last-{}-days".format(days)
            if days <= 0:
                report_name = "workspaces-with-no-login"
            ws_report = create_csv_report(
                report_name, ws_report_headers, filtered_workspaces
            )
            logger.debug("ws_report: {}".format(ws_report))
            reports["Workspaces with no login in last X days"] = ws_report
        elif key == "Workspaces in AutoStart vs AlwaysOn":
            cost_optimiser_files = []
            cost_optimiser_bucket = event["report"][key]["cost-optimiser-bucket"]
            logger.debug("cost_optimiser_bucket: {}".format(cost_optimiser_bucket))
            today_str = today.strftime("%Y-%m-%d")
            yesterday = today - timedelta(days=1)
            yesterday_str = yesterday.strftime("%Y-%m-%d")
            cost_optimiser_key_prefixes = {
                today_str: "{:04d}/{:02d}/{:02d}/".format(
                    today.year, today.month, today.day
                ),
                yesterday_str: "{:04d}/{:02d}/{:02d}/".format(
                    yesterday.year, yesterday.month, yesterday.day
                ),
            }
            for day in cost_optimiser_key_prefixes:
                prefix = cost_optimiser_key_prefixes[day]
                res = aws_function(
                    s3_client.list_objects_v2,
                    Bucket=cost_optimiser_bucket,
                    MaxKeys=100,
                    Prefix=prefix,
                )
                cost_optimiser_files = [
                    content["Key"] for content in res.get("Contents", [])
                ]
                logger.debug("cost_optimiser_files: {}".format(cost_optimiser_files))
                if cost_optimiser_files:
                    break

            filenames = []
            for key in cost_optimiser_files:
                filename = "/tmp/{}".format(key.split("/")[-1])
                filenames.append(filename)
                with open(filename, "wb") as data:
                    s3_client.download_fileobj(cost_optimiser_bucket, key, data)

            new_report_name = "workspaces-in-AutoStart-vs-AlwaysOn"
            headers = [
                "WorkspaceID",
                "Billable Hours",
                "Usage Threshold",
                "Change Reported",
                "Bundle Type",
                "Initial Mode",
                "New Mode",
                "UserID",
                "Directory",
                "Tags",
            ]
            ws_report = merge_csv_reports(new_report_name, headers, day, filenames)
            logger.debug("ws_report: {}".format(ws_report))
            reports["Workspaces in AutoStart vs AlwaysOn"] = ws_report

    ldap_unbind(ldap_con)
    logger.info("Pushing reports to S3")
    logger.debug("reports: {}".format(reports))
    for report_type in reports:
        logger.debug("report_type: {}".format(report_type))
        report_name = reports[report_type]
        bucket_key = "general-report/{}".format(report_name.split("/")[-1])
        event["report"][report_type]["bucket_key"] = bucket_key
        event["report"][report_type]["bucket_name"] = bucket_report
        s3_client.put_object(
            Body=open(report_name, "rb"), Bucket=bucket_report, Key=bucket_key,
        )
    return event
