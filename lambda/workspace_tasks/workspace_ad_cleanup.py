from aws.ssm import SSM
from aws.workspaces import Workspaces
from ldap.ldap import Ldap
import time
import sys

def get_computers_to_remove(ou_list, ldap, search_attribute, aws_current_workspaces_names, logger):

    ldap_computers_to_remove = []
    for ou in ou_list:
        logger.info(
            "Listing computer objects in the following OU: '{}'".format(ou))
        ldap_computers = ldap.ldap_search_computers(ou, search_attribute)

        logger.info("Decoding LDAP search response")
        logger.debug("ldap_computers: {}".format(ldap_computers))

        # List of old computer objects to remove, comparing against AWS as it is the source of truth for ws

        for computer in ldap_computers:
            if computer["name"] not in aws_current_workspaces_names:
                ldap_computers_to_remove.append(computer)

        logger.info(
            "LDAP computer objects retrieved ({amount}) : {comp}".format(
                amount=len(ldap_computers), comp=ldap_computers
            )
        )
        logger.info(
            "LDAP computer objects to be removed ({amount}) : {comp}".format(
                amount=len(ldap_computers_to_remove), comp=ldap_computers_to_remove
            )
        )
    return ldap_computers_to_remove


def cleanup_ad(region, proxy, active_directories, service_username, service_password, ldap_url, max_retries, logger, dry_run):

    search_attribute = ["name", "sAMAccountName", "distinguishedName"]
    ldap = Ldap(ldap_url, service_username, service_password)

    if proxy is None:
        logger.info("Proxy is not defined....!")
        ssm = SSM(region)
        workspaces = Workspaces(region)
    else:
        logger.info("Proxy is defined: {proxy}".format(proxy=proxy))
        ssm = SSM(region, proxy)
        workspaces = Workspaces(region, proxy)

    logger.info("Get current AWS WorkSpaces")
    retries = 0
    aws_current_workspaces = []
    aws_current_workspaces_names = []
    while retries <= max_retries:
        try:
            logger.info("Getting all AWS WorkSpaces")
            aws_current_workspaces = workspaces.get_all_workspaces()
            break
        except Exception as err:
            retries += 1
            time.sleep(5)
            if retries > max_retries:
                logger.error(
                    "Maximun number of retries reached. The exception message is: {}".format(
                        err
                    )
                )
            else:
                logger.warn(
                    "Re-trying ({ret}) - Error is: {er}".format(ret=retries, er=err)
                )

    aws_current_workspaces_names = [
        ws.get("ComputerName", None) for ws in aws_current_workspaces
    ]
    logger.debug("aws_current_workspaces: {}".format(
        aws_current_workspaces))
    logger.debug(
        "aws_current_workspaces_names: {}".format(
            aws_current_workspaces_names)
    )
    logger.info(
        "AWS WorkSpaces: {amount}".format(
            amount=len(aws_current_workspaces_names))
    )
    # If the list of AWS WorkSpaces is empty or all its items (dict) are empty, stop processing immediately
    if not aws_current_workspaces or all(not d for d in aws_current_workspaces):
        logger.error("List of AWS WorkSpaces is empty")
        sys.exit(1)

    logger.info("Searching for computer objects")
    workspaces_ou_list = [
        active_directory["workspaces_organizational_unit"]
        for active_directory in active_directories
    ]
    workspaces_ou_list = list(dict.fromkeys(workspaces_ou_list))
    logger.info(workspaces_ou_list)

    ldap_computers_to_remove = get_computers_to_remove(
        workspaces_ou_list, ldap, search_attribute, aws_current_workspaces_names, logger)

    if not ldap_computers_to_remove:
        logger.info("Nothing to remove")

    elif len(aws_current_workspaces_names) == 0:
        logger.error("No workspaces found")
        sys.exit(1)
    else:
        for computer in ldap_computers_to_remove:
            delete_dn = computer["distinguishedName"]

            if dry_run == "false":
                logger.info(
                    "Deleting computer object: {}".format(delete_dn))
                ldap.ldap_delete(str(delete_dn))
            else:
                logger.info(
                    "[DRY RUN] Deleting computer object: {}".format(
                        delete_dn)
                )

    logger.info("Un-binding LDAP connection")
    ldap.ldap_unbind()

    return "Done"