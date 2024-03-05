import smtplib
from util.logger import get_logger
from aws.ssm import SSM


logger = get_logger()

class SMTP:
    def __init__(self, region, smtp_config):
        self.smtp_config = smtp_config
        self.region = region
        self.ssm = SSM(region)

    def send_email(self, sender, recipients, msg):
        """
        Send email with attachment
        :param sender: from address
        :param recipients: to addresses
        :param msg: message to be sent
        :return:
        """
        smtp_server = self.smtp_config.get("server")
        smtp_port = self.smtp_config.get("port")
        ssm_password_path = self.smtp_config.get("ssm_password_path", None)

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.ehlo()
        server.starttls()  # Secure the connection
        server.ehlo()

        if ssm_password_path:
            logger.info("Retrieving SMTP credentilas")
            smtp_password_parameter = self.ssm.get_parameter(Name=ssm_password_path, WithDecryption=True)
            smtp_password = smtp_password_parameter.get("Parameter").get("Value")
            try:
                logger.info("Authenticating with SMTP server")
                # For authenticated traffic, account used to authenticate must be the one used to send the emails
                server.login(sender, smtp_password)
            except Exception as err:
                logger.error(
                    "Authentication with SMTP server failed. Make sure SMTP AUTH protocol is enabled on the server. Exception: {}".format(
                        err
                    )
                )
                raise
        else:
            logger.warning("SMTP credentials not defined")
            logger.warning("Skipping authentication with SMTP server")

        server.sendmail(sender, recipients, msg.as_string())
        logger.info("Email sent!")