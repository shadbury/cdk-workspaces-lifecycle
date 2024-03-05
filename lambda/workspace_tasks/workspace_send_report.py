import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from util.logger import get_logger
from aws.ses import SES
from aws.s3 import S3
from smtp.smtp import SMTP

logger = get_logger()


def send_email(region, sender, recipients, subject, body, attachments, smtp_config, mail_service):
    """
    Send email with attachment
    :param ses_client: AWS SES client
    :param sender: from address
    :param recipients: to addresses
    :param subject: subject of the email
    :param body: body of the email
    :param attachment: file to be sent
    :return:
    """

    CHARSET = "utf-8"
    msg = MIMEMultipart("mixed")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ",".join(recipients)
    msg_body = MIMEMultipart("alternative")
    textpart = MIMEText(body.encode(CHARSET), "plain", CHARSET)
    msg_body.attach(textpart)
    msg.attach(msg_body)

    for attachment in attachments:
        att = MIMEApplication(open(attachment, "rb").read())
        att.add_header("Content-Disposition", "attachment",
                       filename=os.path.basename(attachment))
        msg.attach(att)
    try:
        logger.info("Using [{}] as mail service".format(mail_service))
        if mail_service == "ses":
            ses = SES(region)
            response = ses.send_email(sender, recipients, msg.as_string())
        else:
            smtp = SMTP(region, smtp_config)
            smtp.sendmail(sender, recipients, msg.as_string())
    except Exception as err:
        logger.error("Error sending email: {}".format(err))
        raise


def retrieve_from_s3(region, bucket_name, bucket_key):
    file_path = "/tmp/{}".format(bucket_key.split("/")[-1])
    s3 = S3(region)
    s3.download_file(bucket_name, bucket_key, file_path)
    return file_path


def lambda_handler(region, dry_run, mail_service, event):

    sender = event["email"]["sender"]
    recipients = event["email"]["recipients"]
    ws_reports = []
    subject = (
        "[DRY RUN] - {}".format(event["email"]["subject"])
        if dry_run == "true"
        else event["email"]["subject"]
    )
    body = event["email"]["body"]
    smtp_config = None
    if mail_service == "smtp":
        smtp_config = event["email"]["smtp_config"]
    logger.info("Retrieving report information from event")
    for key in event["report"]:
        try:
            bucket_name = event["report"][key]["bucket_name"]
            bucket_key = event["report"][key]["bucket_key"]
            ws_reports.append(retrieve_from_s3(bucket_name, bucket_key))
        except Exception as err:
            logger.error("key: {} - Exeption is: {}".format(key, err))
            raise

    logger.info("Attempting to send email")
    send_email(region, sender, recipients, subject, body,
               ws_reports, smtp_config, mail_service)
    return event