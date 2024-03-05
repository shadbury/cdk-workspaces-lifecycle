from aws.workspaces import Workspaces
from aws.kms import KmsManager
from aws.directory import DirectoryManager
from ldap.ldap import Ldap
from util.logger import get_logger
from util.formatter import sanitise_tag
import os
import ast

logger = get_logger()


def user_sync(
    region,
    active_directory,
    ad_admin_username,
    ad_admin_password,
    ldap_url,
    domain_base_dn,
    logger,
    dry_run,
    proxy = None,
):

    all_directory_ids = []
    created_workspaces_details = []
    failed_workspaces_errors = {}
    extra_tags = ast.literal_eval(
        os.getenv("EXTRA_TAGS") if os.getenv("EXTRA_TAGS") else "[]"
    )
    if proxy:
        workspace_client = Workspaces(region, proxy)
    else:
        workspace_client = Workspaces(region)
        
    ldap = Ldap(ldap_url, ad_admin_username, ad_admin_password)

    for ad in active_directory:
        all_directory_ids.extend([ad_id for ad_id in ad["directory_ids"]])

    logger.info("searching workspaces")
    registration_code_map = workspace_client.search_directory_registration_code(
        all_directory_ids
    )

    logger.info("mapping workspace directories")
    workspace_user_directories = workspace_client.get_workspaces_directories()

    logger.info("initializing kms manager")
    kms_manager = KmsManager(
        [active_directory["group_name"] for active_directory in active_directory]
    )

    logger.info("initializing directory manager")
    directory_manager = DirectoryManager(workspace_user_directories, active_directory)

    logger.info("searching for users in AD using the provided search filter")
    for active_directory in active_directory:
        ad_group_name = active_directory["group_name"]
        user_group_cns = active_directory["group_cns"]
        bundle_id = active_directory["bundle_id"]
        workspaces_ou = active_directory["workspaces_organizational_unit"]
        directory_ids = [ad_id for ad_id in active_directory["directory_ids"]]
        workspace_users_in_group = []

        logger.info(
            "[{}] Searching for users in AD using the provided search filter".format(
                ad_group_name
            )
        )

        ldap_users, ldap_user_info = ldap.ldap_search_users(
            domain_base_dn, user_group_cns
        )

        logger.info("[{}] Listed users: {}".format(ad_group_name, ldap_users))

        logger.info("[{}] Searching for all workspaces".format(ad_group_name))
        for directory_id in directory_ids:
            if directory_id in workspace_user_directories:
                workspace_users_in_group.extend(
                    workspace_user_directories[directory_id]
                )

        logger.debug(
            "[{}] List of users with a workspace:".format(
                ad_group_name, workspace_users_in_group
            )
        )

        new_accounts = list(set(ldap_users).difference(workspace_users_in_group))

        logger.info(
            "[{}] List of AD users without a workspace: {}".format(
                ad_group_name, new_accounts
            )
        )

        deleted_accounts = list(set(workspace_users_in_group).difference(ldap_users))
        logger.info(
            "[{}] List of users with a workspace not present in AD: {}".format(
                ad_group_name, deleted_accounts
            )
        )

        logger.info(
            "[{}] Retrieve bundle [{}] details".format(ad_group_name, bundle_id)
        )
        bundle_details = workspace_client.describe_workspace_bundles(
            BundleIds=[bundle_id]
        )

        logger.debug("[{}] bundle_details {}: ".format(ad_group_name, bundle_details))

        try:
            image_id = bundle_details["Bundles"][0].get("ImageId", "None")
            bundle_name = bundle_details["Bundles"][0].get("Name", "None")
            bundle_description = bundle_details["Bundles"][0].get("Description", "None")
        except Exception as err:
            logger.error(
                "Bundle not found. Check if bundle [{}] exists. Error is: {}".format(
                    bundle_id, err
                )
            )

        logger.info("[{}] Retrieve image [{}] details".format(ad_group_name, image_id))
        image_details = workspace_client.describe_workspace_images(ImageIds=[image_id])
        logger.debug("[{}] image_details {}: ".format(ad_group_name, image_details))

        try:
            image_name = image_details["Images"][0].get("Name", "None")
            image_description = image_details["Images"][0].get("Description", "None")
        except Exception as err:
            logger.error(
                "Image not found. Check if image [{}] exists. Error is: {}".format(
                    bundle_id, err
                )
            )

        if new_accounts:
            while (
                new_accounts
            ):  # AWS only takes in batches of 25, so split into batches
                new_workspaces = []
                batch = new_accounts[0:20]
                new_accounts = new_accounts[20:]
                for account in batch:
                    new_workspace = {}
                    default_tags = [
                        {"Key": "AdGroupName", "Value": sanitise_tag(ad_group_name)},
                        {
                            "Key": "AdDepartment",
                            "Value": sanitise_tag(
                                ldap_user_info[account]["department"][:255]
                            ),
                        },
                        {
                            "Key": "AdDepartmentNumber",
                            "Value": sanitise_tag(
                                ldap_user_info[account]["department_number"][:255]
                            ),
                        },
                        {
                            "Key": "AdGroupCN",
                            "Value": sanitise_tag("-".join(user_group_cns)[:255]),
                        },
                        {
                            "Key": "AdComputerOU",
                            "Value": sanitise_tag(workspaces_ou[:255]),
                        },
                        {
                            "Key": "AdFullName",
                            "Value": ldap_user_info[account].get("full_name"),
                        },
                        {
                            "Key": "AdGivenName",
                            "Value": ldap_user_info[account].get("given_name"),
                        },
                        {
                            "Key": "AdSurname",
                            "Value": ldap_user_info[account].get("surname"),
                        },
                        {"Key": "DirectoryId", "Value": directory_id},
                        {"Key": "BundleId", "Value": bundle_id},
                        {"Key": "BundleName", "Value": sanitise_tag(bundle_name)},
                        {
                            "Key": "BundleDescription",
                            "Value": sanitise_tag(bundle_description),
                        },
                        {"Key": "ImageId", "Value": image_id},
                        {"Key": "ImageName", "Value": sanitise_tag(image_name)},
                        {
                            "Key": "ImageDescription",
                            "Value": sanitise_tag(image_description),
                        },
                    ]

                    if extra_tags:
                        logger.debug("extra_tags: {}".format(extra_tags))
                        for extra_tag in extra_tags:
                            try:
                                # Raise exeption if below keys are not present
                                logger.info(
                                    "Adding extra tag [{}] = [{}]".format(
                                        extra_tag.get("Key"), extra_tag.get("Value")
                                    )
                                )
                                default_tags.append(extra_tag)
                            except Exception as err:
                                logger.warning(
                                    "Could not append all extra tags. Error is: {}".format(
                                        err
                                    )
                                )

                    new_workspace["DirectoryId"] = directory_manager.get_directory_id(
                        ad_group_name, account
                    )
                    new_workspace["UserName"] = account
                    new_workspace["RootVolumeEncryptionEnabled"] = True
                    new_workspace["UserVolumeEncryptionEnabled"] = True
                    new_workspace["VolumeEncryptionKey"] = kms_manager.get_key_id(
                        ad_group_name
                    )
                    new_workspace["BundleId"] = bundle_id
                    new_workspace["WorkspaceProperties"] = {
                        "RunningMode": os.getenv("RUNNINGMODE"),
                        "RunningModeAutoStopTimeoutInMinutes": int(
                            os.getenv("USAGETIMEOUT")
                        ),
                    }
                    new_workspace["Tags"] = default_tags
                    new_workspaces.append(new_workspace)

                if dry_run == "false":
                    logger.info(
                        "[{}] New workspaces: {}".format(ad_group_name, new_workspaces)
                    )
                    create_result = workspace_client.create_workspaces(
                        Workspaces=new_workspaces
                    )

                    for pending_result in create_result.get("PendingRequests", []):
                        created_workspaces_details.append(
                            {
                                "workspace_id": pending_result["WorkspaceId"],
                                "user_name": pending_result["UserName"],
                                "mail": ldap_user_info[pending_result["UserName"]][
                                    "mail"
                                ],
                                "registration_code": registration_code_map[
                                    pending_result["DirectoryId"]
                                ],
                            }
                        )
                    for failed_request in create_result.get("FailedRequests", []):
                        logger.debug("failed_request: {}".format(failed_request))
                        failed_workspaces_errors[
                            failed_request["WorkspaceRequest"]["UserName"]
                        ] = {
                            "ErrorCode": failed_request["ErrorCode"],
                            "ErrorMessage": failed_request["ErrorMessage"],
                        }
                else:
                    logger.info(
                        "[DRY RUN] [{}] New workspaces: {}".format(
                            ad_group_name, new_workspaces
                        )
                    )
                    create_result = {"create_workspaces": "Currently disabled"}
                    for account in batch:
                        created_workspaces_details.append(
                            {
                                "workspace_id": "xxxxDryRunxxx",
                                "user_name": account,
                                "mail": ldap_user_info[account]["mail"],
                                "registration_code": "xxxxDryRunxxx",
                            }
                        )
                logger.info("[{}] Workspaces created".format(ad_group_name))
                logger.info("[{}] Result: {}".format(ad_group_name, create_result))
