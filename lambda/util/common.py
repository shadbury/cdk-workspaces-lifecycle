

def fatal_code(e):
    '''
    Returns True if the error is not a RequestLimitExceeded error
    '''
    return e.response.get('Error', {}).get('Code', 'Unknown') != 'RequestLimitExceeded'


def convert_tag_list_to_map(tag_list):
    tag_map = {}
    for tag_obj in tag_list:
        tag_map[tag_obj["Key"]] = tag_obj["Value"]
    return tag_map