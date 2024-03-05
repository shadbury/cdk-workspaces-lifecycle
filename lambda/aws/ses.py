import boto3
from botocore.exceptions import ClientError
from util.logger import get_logger

logger = get_logger()


class SES:
    def __init__(self, region_name):
        self.region_name = region_name
        self.client = self.get_ses_client()

    def get_ses_client(self):
        """
        Connect to AWS SES
        :return: SES client
        """
        return boto3.client("ses", region_name=self.region_name)

    def send_email(self, sender, recipients, msg):
        """
        Send email with attachment
        :param sender: from address
        :param recipients: to addresses
        :param subject: subject of the email
        :param body: body of the email
        :param attachment: file to be sent
        :return:
        """

        try:
            # Provide the contents of the email.
            response = self.client.send_raw_email(
                Source=sender,
                Destinations=recipients,
                RawMessage={"Data": msg.as_string()},
            )
        except ClientError as e:
            logger.error(e.response["Error"]["Message"])
        else:
            logger.info("Email sent! Message ID:"),
            print(response["MessageId"])
