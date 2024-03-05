import re

def decode(encoded_value):
    """
    Decodes bytes
    :param l: list of bytes
    :return: decoded value
    """
    if isinstance(encoded_value, list):
        decoded_list = []
        for item in encoded_value:
            if isinstance(item, bytes):
                decoded_list.append(item.decode("utf-8"))
        return decoded_list
    elif isinstance(encoded_value, bytes):
        return encoded_value.decode("utf-8")
    else:
        return encoded_value
    
def sanitise_tag(tag):
    key_pattern = re.compile(r"[a-zA-Z0-9_.:/=+\-@ ]+")
    return "".join(re.findall(key_pattern, tag.replace(",", " ")))