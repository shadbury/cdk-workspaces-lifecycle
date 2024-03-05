from enum import Enum
from dateutil.tz import gettz
from pytz import timezone



class Defaults(Enum):
    
    MAX_TRIES = 3
    LOCAL_TIMEZONE = timezone("Australia/Sydney")
    TZ_INFOS = {"AEST": gettz("Australia/Sydney")}
    MAX_WORKSPACES_PER_KMS_KEY = 495
    MAX_WORKSPACES_PER_AD_CONNECTOR = {"Small": 495, "Large": 4995}