import os
from aws.ses import SES
from smtp.smtp import SMTP
from util.logger import get_logger
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = get_logger

def send_email(region, sender, recipients, subject, body, smtp_config, mail_service):
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


def notify_user(event, region, mail_service):
    sender = event["email"]["sender"]
    support_mail = event["email"].get("support_mail")
    smtp_config = None
    if mail_service == "smtp":
        smtp_config = event["email"]["smtp_config"]
    subject = "Your Amazon WorkSpace"
    general_body = (
        "Dear User,<br/><br/>"
        "A new Amazon WorkSpace has been created for you. "
        "Please allow at least 1 hour from receipt of this email before attempting to log onto your workspace. "
        "Follow the steps below to quickly get started with your WorkSpace:<br/><br/>"
        "1. Download a WorkSpaces client using the following link:<br/>"
        "https://clients.amazonworkspaces.com/<br/><br/>"
        "2. Launch the client and enter the following registration code: {registration_code}<br/><br/>"
        "3. Login using your credentials. Your username is: <b>{user_name}</b>.<br/><br/><br/>"
        "If you have any issues connecting to your WorkSpace, please contact {support_info}"
    )

    created_workspaces_details = event.get("created_workspaces_details", [])
    mails_in_error = {}
    for created_workspace in created_workspaces_details:
        recipient = created_workspace["mail"]
        user_name = created_workspace["user_name"]
        if recipient == "None":
            mails_in_error[user_name] = {
                "ErrorMessage": "The user does not have an email address in Active Directory"
            }
            continue
        registration_code = created_workspace["registration_code"]
        support_info = (
            '<a href = "mailto: {mail}">{mail}</a>'.format(mail=support_mail)
            if support_mail
            else "your administrator"
        )
        body = general_body.format(
            registration_code=registration_code,
            user_name=user_name,
            support_info=support_info,
        )
        try:
            send_email(sender, recipient, subject, body, smtp_config)
        except Exception as e:
            mails_in_error[user_name] = {"ErrorMessage": str(e)}
    if mails_in_error:
        if "errors" not in event:
            event["errors"] = {}
        event["errors"].update(mails_in_error)
    return event
