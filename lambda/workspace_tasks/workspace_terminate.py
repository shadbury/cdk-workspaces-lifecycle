import sys
from util.defaults import LOCAL_TIMEZONE, TZ_INFOS
from util.report_helper import create_csv_report
from datetime import datetime, timedelta
from dateutil.parser import parse
from aws.workspaces import Workspaces
from aws.s3 import S3
from ldap.ldap import Ldap
from util.logger import get_logger
from util.common import decode

logger = get_logger


def get_ldap_users(ldap_users):
    ldap_users_map = {}
    for user in ldap_users:
        user_cn = decode(user)
        account_name = decode(user["sAMAccountName"][0])
        account_email = decode(user["mail"][0]) if user["mail"] else "None"
        account_department = (
            decode(user["department"][0]) if user["department"] else "None"
        )
        account_department_number = (
            decode(user["departmentNumber"][0])
            if user["departmentNumber"]
            else "None"
        )
        user_full_name = decode(user["name"][0]) if user["name"] else "None"
        user_given_name = (
            decode(user["givenName"][0]) if user["givenName"] else "None"
        )
        user_surname = decode(user["sn"][0]) if user["sn"] else "None"
        ldap_users_map[account_name] = {
            "full_name": user_full_name.replace(",", " "),
            "given_name": user_given_name.replace(",", " "),
            "surname": user_surname.replace(",", " "),
            "user_id": account_name,
            "cn": user_cn,
            "mail": account_email,
            "department": account_department.replace(",", " "),
            "department_number": account_department_number.replace(",", " "),
        }
    return ldap_users_map


def get_removed_users(ldap_users_ids, aws_current_workspaces):
    workspaces_from_users_not_in_ad = []
    for workspace in aws_current_workspaces:
        if workspace["UserName"] not in ldap_users_ids:
            workspace["Reason"] = "User not in AD group"
            workspaces_from_users_not_in_ad.append(workspace)
    return workspaces_from_users_not_in_ad


def get_disabled_users(ldap_disabled_acc_ids, aws_current_workspaces):
    workspaces_from_disabled_acc = []
    for workspace in aws_current_workspaces:
        if workspace["UserName"] in ldap_disabled_acc_ids:
            workspace["Reason"] = "Disabled account"
            workspaces_from_disabled_acc.append(workspace)
    return workspaces_from_disabled_acc


def get_seach_filter_users_body(group_cn_list):
    search_filter_users_body = []
    for group_cn in group_cn_list:
        search_filter_aux = "(memberOf={group_cn})".format(group_cn=group_cn)
        search_filter_users_body.append(search_filter_aux)
    return search_filter_users_body


def terminate(
    region,
    event,
    proxy,
    active_directories,
    service_username,
    service_password,
    ldap_url,
    bucket_report,
    domain_base_dn,
    excluded_accounts,
    retention,
    enable_delete,
    dry_run,
):
    # Initialize variables

    if proxy:
        workspaces = Workspaces(region, proxy)
    else:
        workspaces = Workspaces(region)
    s3 = S3(region)

    users_search_attribute = [
        "sAMAccountName",
        "name",
        "givenName",
        "sn",
        "distinguishedName",
        "mail",
        "department",
        "departmentNumber",
    ]

    ldap = Ldap(ldap_url, service_username, service_password)
    workspaces_to_terminate = []

    logger.info("Getting all current AWS WorkSpaces")
    aws_current_workspaces = workspaces.get_all_workspaces()
    aws_current_workspaces_names = [
        ws.get("ComputerName", None) for ws in aws_current_workspaces
    ]
    aws_current_workspaces_user_ids = [
        ws.get("UserName", None) for ws in aws_current_workspaces
    ]
    logger.debug(
        "aws_current_workspaces_names: {names} ({count})".format(
            names=aws_current_workspaces_names, count=len(
                aws_current_workspaces_names)
        )
    )
    logger.debug(
        "aws_current_workspaces_user_ids: {ids} ({count})".format(
            ids=aws_current_workspaces_user_ids,
            count=len(aws_current_workspaces_user_ids),
        )
    )

    # If the list of AWS WorkSpaces is empty or all its items (dict) are empty, stop processing immediately
    if not aws_current_workspaces or all(not d for d in aws_current_workspaces):
        logger.error("List of AWS WorkSpaces is empty")
        sys.exit(1)

    # Iterating through each directory to get users
    for active_directory in active_directories:
        directory_ids = [ad_id for ad_id in active_directory["directory_ids"]]
        group_cn_list = active_directory["group_cns"]
        group_name = active_directory["group_name"]
        logger.debug(
            "directory_ids: {} | group_cn_list: {}".format(
                directory_ids, group_cn_list)
        )
        search_filter_users_body = get_seach_filter_users_body(
            group_cn_list)

        if len(group_cn_list) > 1:
            search_filter_users = "(&(objectCategory=user)(|{ad_groups}))".format(
                ad_groups="".join(search_filter_users_body)
            )
        else:
            search_filter_users = "(&(objectCategory=user){ad_groups})".format(
                ad_groups="".join(search_filter_users_body)
            )

        search_filter_disabled = "(&(objectCategory=person)(objectClass=user)(|{ad_groups})(userAccountControl:1.2.840.113556.1.4.803:=2))".format(
            ad_groups="".join(search_filter_users_body)
        )
        logger.debug("search_filter_users: {}".format(search_filter_users))
        logger.debug("search_filter_disabled: {}".format(
            search_filter_disabled))

        logger.info(
            "Searching for members of [{dir}] | {group_name}".format(
                dir=directory_ids, group_name=group_name
            )
        )

        ldap_users = ldap.ldap_search_users(domain_base_dn, group_cn_list)

        logger.info("Decoding LDAP search response")
        ldap_users_map = get_ldap_users(ldap_users)
        logger.debug("ldap_users_map: {}".format(ldap_users_map))

        ldap_users_ids = [
            user["sAMAccountName"] for user in ldap_users if user["sAMAccountName"]
        ]

        logger.info(
            "ldap_users_ids of {group_name} ({count}) : {ws}".format(
                group_name=group_name, count=len(ldap_users_ids), ws=ldap_users_ids
            )
        )

        logger.info(
            "Searching for disabled user accounts in {group_name}".format(
                group_name=group_name
            )
        )
        ldap_disabled_accounts = ldap.ldap_search(
            domain_base_dn, search_filter_disabled, users_search_attribute
        )

        logger.info("Decoding LDAP search response")
        for elem in ldap_disabled_accounts:
            for key, value in elem.items():
                # Decode bytes and convert list of 1 element to string or integer as needed
                elem[key] = "".join(decode(value))

        ldap_disabled_acc_ids = [
            user.get("sAMAccountName")
            for user in ldap_disabled_accounts
            if user.get("sAMAccountName", None)
        ]
        logger.debug(
            "ldap_disabled_acc_ids of [{group_name}] ({count}) : {ws}".format(
                group_name=group_name,
                count=len(ldap_disabled_acc_ids),
                ws=ldap_disabled_acc_ids,
            )
        )

        logger.info(
            "Searching for Workspaces assigned to [{dir}] | {group_name} or to disabled users accounts".format(
                dir=directory_ids, group_name=group_name
            )
        )
        workspaces_from_users_not_in_ad = get_removed_users(
            ldap_users_ids, aws_current_workspaces)
        
        workspaces_from_disabled_acc = get_disabled_users(
            ldap_disabled_acc_ids, aws_current_workspaces)
        
        logger.info("Workspaces marked for termination")
        workspaces_to_terminate.extend(workspaces_from_disabled_acc)
        workspaces_to_terminate.extend(workspaces_from_users_not_in_ad)
        logger.info(
            "workspaces_to_terminate ({}) : {}".format(
                len(workspaces_to_terminate), workspaces_to_terminate
            )
        )

    logger.info("Filtering CMD Admin workspaces from termination")

    workspaces_to_terminate_aux = workspaces_to_terminate.copy()
    for ws in workspaces_to_terminate_aux:
        if excluded_accounts.get(ws["UserName"], None):
            workspaces_to_terminate.remove(ws)
            logger.info("workspaces_to_terminate - removed: {}".format(ws))

    logger.info("Terminating Workspaces")
    logger.info(
        "workspaces to terminate or schedule [{}]: \n {}".format(
            len(workspaces_to_terminate), workspaces_to_terminate
        )
    )
    failed_workspaces_errors = {}
    today = (
        datetime.utcnow()
        .astimezone(LOCAL_TIMEZONE)
        .replace(hour=0, minute=0, second=0, microsecond=0)
    )
    
    
    
    for ws in workspaces_to_terminate:
        termination_date_str = ws["Tags"].get("TerminationDate", None)
        if termination_date_str:
            try:
                termination_date = parse(
                    termination_date_str, tzinfos=TZ_INFOS
                ).astimezone(LOCAL_TIMEZONE)
            except Exception as e:
                logger.error(
                    "Unknown termination date: {}".format(termination_date_str)
                )
                termination_date_str = None
        if not termination_date_str:
            termination_date = today + timedelta(days=retention)
            termination_date_str = termination_date.strftime(
                "%Y-%m-%d %H:%M:%S %Z")

            response = workspaces.modify_workspace_properties(
                ws["WorkspaceId"], {"RunningMode": "AUTO_STOP"}
            )
            if response == "InvalidResourceStateException":
                response = workspaces.get_workspaces(ws["WorkspaceId"])
                ws_state = response["Workspaces"][0]["State"]
                logger.warning(
                    "Workspace [{}] is in state [{}]. Exception: {}".format(
                        ws["WorkspaceId"], ws_state, e
                    )
                )
            else:
                logger.error(
                    "Exception when modifying Workspace [{}]. Exception: {}".format(
                        ws["WorkspaceId"], e
                    )
                )
                raise e

            workspaces.create_tags(
                ws["WorkspaceId"],
                [
                    {"Key": "TerminationDate", "Value": termination_date_str},
                    {"Key": "Skip_Convert", "Value": ""},
                ],
            )

        if today >= termination_date:
            if dry_run == "false":
                ws["Action"] = "Terminated today. Date: {}".format(
                    termination_date_str)
                logger.debug(
                    "terminate_workspace: {}".format(ws["WorkspaceId"]))
                res = workspaces.terminate_workspaces(ws["WorkspaceId"])
                for failed_request in res.get("FailedRequests", []):
                    failed_workspaces_errors[failed_request["WorkspaceId"]] = {
                        "ErrorCode": failed_request["ErrorCode"],
                        "ErrorMessage": failed_request["ErrorMessage"],
                    }
            else:
                ws["Action"] = "DRY_RUN - Terminated today. Date: {}".format(
                    termination_date_str
                )
                dry_run = "true"
                logger.warning(
                    "Terminate action DISABLED. To enable it make sure to set [DRY_RUN=false] environment variable"
                )
            if (
                enable_delete == "true"
                and ws["WorkspaceId"] not in failed_workspaces_errors
            ):
                logger.info("Querying LDAP for {}".format(ws["ComputerName"]))
                computer_filter = "(&(objectCategory=computer)(name={}))".format(
                    ws["ComputerName"]
                )
                computer_search_attribute = ["distinguishedName"]
                computer_dn_res = ldap.ldap_search(
                    domain_base_dn, computer_filter, computer_search_attribute
                )
                if len(computer_dn_res) != 1:
                    logger.error(
                        "LDAP query returned 0 or more than one object. Res: {}".format(
                            computer_dn_res
                        )
                    )
                    continue
                computer_dn = computer_dn_res[0]["distinguishedName"]
                if dry_run == "false":
                    logger.info(
                        "Deleting computer object: {}".format(computer_dn))
                    ldap.ldap_delete(str(computer_dn))
                else:
                    logger.warning(
                        "[DRY RUN] Deleting computer object: {}".format(
                            computer_dn)
                    )
        else:
            left_days = (termination_date - today).days
            logger.debug(
                "{} scheduled to be deleted in {} days. Date: {}".format(
                    ws["WorkspaceId"], left_days, termination_date_str
                )
            )
            ws["Action"] = "Scheduled to be deleted in {} days. Date: {}".format(
                left_days, termination_date_str
            )

    logger.info("Un-binding LDAP connection")
    ldap.ldap_unbind()

    logger.info("Generating CSV report")
    ws_report_headers = [
        "UserName",
        "AdFullName",
        "AdGivenName",
        "AdSurname",
        "AdGroupName",
        "WorkspaceId",
        "DirectoryId",
        "ComputerName",
        "Action",
        "Reason",
    ]
    ws_report = create_csv_report(
        "workspaces-report-termination", ws_report_headers, workspaces_to_terminate
    )

    logger.info("Pushing report to S3")
    bucket_key = "terminate-report/{}".format(ws_report.split("/")[-1])
    event["report"] = {
        "workspaces-report-termination": {
            "bucket_key": bucket_key,
            "bucket_name": bucket_report,
        }
    }
    s3.put_object(open(ws_report, "rb"), bucket_report, bucket_key)

    if failed_workspaces_errors:
        if "errors" not in event:
            event["errors"] = {}
        event["errors"].update(failed_workspaces_errors)

    return event
