from workspace_tasks.workspace_ad_cleanup import cleanup_ad
from workspace_tasks.workspace_user_sync import user_sync
from workspace_tasks.workspace_terminate import terminate
from workspace_tasks.workspace_poll_on_creation import poll
from aws.ssm import SSM
from util.logger import get_logger
from util.defaults import MAX_TRIES
import os

logger = get_logger()


def end(event, context):
    logger.info("End of the execution")
    if "errors" in event:
        raise Exception("Registered errors: {}".format(event["errors"]))
    return event


def lambda_handler(event, context):

    ssm = SSM(event["region"])

    # Environment variables
    SSM_PASSWORD_PATH = os.environ.get("SSM_PASSWORD_PATH")
    SMTP_PASSWORD_PATH = os.environ.get("SMTP_PASSWORD")
    enable_delete = os.environ.get("ENABLE_DELETE_COMPUTER_OBJECTS")
    region = event["region"]
    proxy = os.environ.get("PROXY_URL")
    active_directories = event["active_directories"]
    service_account = os.getenv("SERVICE_ACCOUNT")
    ldap_url = os.getenv("LDAP_URL")
    domain_base_dn = os.getenv("DOMAIN_BASE_DN")
    dry_run = os.getenv("DRY_RUN", "true")

    passwordecoded = ssm.get_parameter(
        Name=SSM_PASSWORD_PATH, WithDecryption=True)

    mail_service = os.environ.get("MAIL_SERVICE")
    retention = os.environ.get("RETENTION")
    bucket_report = os.environ.get("BUCKET_REPORT")
    excluded_accounts = os.environ.get("EXCLUDED_ACCOUNTS")

    if mail_service not in ["ses", "smtp"]:
        raise Exception(
            "Mail service value not recognised. Allowed values: ses, smtp")

    if event["action"] == "cleanup_ad":

        cleanup_ad(
            region,
            proxy,
            active_directories,
            service_account,
            passwordecoded,
            ldap_url,
            MAX_TRIES,
            logger,
            dry_run,
        )

    if event["action"] == "user_sync":

        user_sync(
            region,
            proxy,
            active_directories,
            service_account,
            passwordecoded,
            ldap_url,
            domain_base_dn,
            logger,
            dry_run,
        )

    if event["action"] == "terminate":

        terminate(
            region,
            event,
            proxy,
            active_directories,
            service_account,
            passwordecoded,
            ldap_url,
            bucket_report,
            domain_base_dn,
            excluded_accounts,
            retention,
            enable_delete,
            dry_run,
        )

    if event["action"] == "poll":
        poll(
            region,
            event,
            proxy
        )

    if event["action"] == "notify":
        pass

    if event["action"] == "end":
        end(event, context)
