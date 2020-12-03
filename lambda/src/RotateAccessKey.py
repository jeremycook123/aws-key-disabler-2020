import boto3
from datetime import datetime
import dateutil.tz
import json
import ast
import re

BUILD_VERSION = '@@buildversion'
AWS_REGION = '@@deploymentregion'
USERNAMES_SKIP = @@usernamesskip

EMAIL_FROM = '@@emailfrom'
EMAIL_ADMIN = ast.literal_eval('@@emailadmin')
EMAIL_ADMIN_TO = '@@emailadminto'
EMAIL_USER_CONFIG = ast.literal_eval('@@emailuser')

EMAIL_REGEX = re.compile(r'[^@]+@[^@]+\.[^@]+')

# Length of mask over the IAM Access Key
MASK_ACCESS_KEY_LENGTH = ast.literal_eval('@@maskaccesskeylength')

# First email warning
FIRST_WARNING_NUM_DAYS = @@first_warning_num_days
FIRST_WARNING_MESSAGE = '@@first_warning_message'
# Last email warning
LAST_WARNING_NUM_DAYS = @@last_warning_num_days
LAST_WARNING_MESSAGE = '@@last_warning_message'

# Max AGE days of key after which it is considered EXPIRED (deactivated)
KEY_MAX_AGE_IN_DAYS = @@key_max_age_in_days
KEY_EXPIRED_MESSAGE = '@@key_expired_message'

KEY_YOUNG_MESSAGE = '@@key_young_message'

# ==========================================================

# Character length of an IAM Access Key
ACCESS_KEY_LENGTH = 20
KEY_STATE_ACTIVE = "Active"
KEY_STATE_INACTIVE = "Inactive"

# ==========================================================

#check to see if the MASK_ACCESS_KEY_LENGTH has been misconfigured
if MASK_ACCESS_KEY_LENGTH > ACCESS_KEY_LENGTH:
    MASK_ACCESS_KEY_LENGTH = 16

# ==========================================================
def tzutc():
    return dateutil.tz.tzutc()


def key_age(key_created_date):
    tz_info = key_created_date.tzinfo
    age = datetime.now(tz_info) - key_created_date

    key_age_str = str(age)
    if 'days' not in key_age_str:
        return 0

    days = int(key_age_str.split(',')[0].split(' ')[0])

    return days

def send_invaliduseremailaddress_email(email_to, username, tagname):
    client = boto3.client('ses', region_name=AWS_REGION)
    response = client.send_email(
        Source=EMAIL_FROM,
        Destination={
            'ToAddresses': [email_to]
        },
        Message={
            'Subject': {
                'Data': 'Missing Email Tag for User: %s' % username
            },
            'Body': {
                'Html': {
                'Data': 'The Tag [%s] belonging to User [%s] does not contain a valid email address. Please review and check within IAM.' % (tagname, username)
                }
            }
        })

def send_deactivate_email(email_to, username, age, access_key_id):
    client = boto3.client('ses', region_name=AWS_REGION)
    response = client.send_email(
        Source=EMAIL_FROM,
        Destination={
            'ToAddresses': [email_to]
        },
        Message={
            'Subject': {
                'Data': 'AWS IAM Access Key Rotation - Deactivation of Access Key: %s' % access_key_id
            },
            'Body': {
                'Html': {
                'Data': 'The Access Key [%s] belonging to User [%s] has been automatically deactivated due to it being %s days old' % (access_key_id, username, age)
                }
            }
        })


def send_completion_email(email_to, finished, deactivated_report):
    client = boto3.client('ses', region_name=AWS_REGION)
    response = client.send_email(
        Source=EMAIL_FROM,
        Destination={
            'ToAddresses': [email_to]
        },
        Message={
            'Subject': {
                'Data': 'AWS IAM Access Key Rotation - Lambda Function'
            },
            'Body': {
                'Html': {
                'Data': 'AWS IAM Access Key Rotation Lambda Function (cron job) finished successfully at %s\n\nDeactivation Report:\n%s' % (finished, deactivated_report)
                }
            }
        })

#Will send email containing one of the following messages:
#Your AWS IAM Access Key (****************34MI) is due to expire in 1 week (7 days) - please rotate.
#Your AWS IAM Access Key (****************34MI) is due to expire in 1 day (tomorrow) - please rotate.
#Your AWS IAM Access Key (****************34MI) is now EXPIRED! Changing key to INACTIVE state - please rotate.
def send_user_email(email_to, key, message):
    if not email_to or not EMAIL_REGEX.match(email_to):
        return

    client = boto3.client('ses', region_name=AWS_REGION)
    response = client.send_email(
        Source=EMAIL_FROM,
        Destination={
            'ToAddresses': [email_to]
        },
        Message={
            'Subject': {
                'Data': 'AWS IAM Access Key Rotation'
            },
            'Body': {
                'Html': {
                'Data': 'Your AWS IAM Access Key (%s) %s.' % (key, message)
                }
            }
        })

def mask_access_key(access_key):
    return access_key[-(ACCESS_KEY_LENGTH-MASK_ACCESS_KEY_LENGTH):].rjust(len(access_key), "*")


def lambda_handler(event, context):
    print('*****************************')
    print(f'RotateAccessKey v{BUILD_VERSION}: starting...')
    print("*****************************")
    # Connect to AWS APIs
    client = boto3.client('iam')

    users = {}
    data = client.list_users()

    userindex = 0

    for user in data['Users']:
        userid = user['UserId']
        username = user['UserName']    
        
        usertags = client.list_user_tags(UserName=username)

        users[userid] = { "username": username, "tags": usertags}

    users_report = []

    users_list_first_warning = []
    users_list_last_warning = [] 
    users_list_keys_deactivated = []
    users_list_email_tag_invalid = []

    email_user_enabled = False

    try:
        email_user_enabled = EMAIL_USER_CONFIG["enabled"]
    except:
        pass

    for user in users:
        email_user_address = None

        userindex += 1
        user_keys = []

        username = users[user]["username"]
        usertags = users[user]["tags"]

        # check to see if the current user is a special service account
        if username in USERNAMES_SKIP:
            print(f'detected special username (configured service account etc.) {username}, key rotation skipped for this account...')
            continue

        # determine if USER based email address is configured
        # can be either username based or tag based
        if email_user_enabled:
            try:
                if EMAIL_USER_CONFIG["emailaddressconfig"]["type"] == "username":
                    if EMAIL_REGEX.match(username):
                        email_user_address = username
                elif EMAIL_USER_CONFIG["emailaddressconfig"]["type"] == "tag":
                    validuseremailaddress = False
                    for tag in usertags["Tags"]:
                        if tag["Key"] == EMAIL_USER_CONFIG["emailaddressconfig"]["tagname"]:
                            tag_emailaddress = tag["Value"]
                            if EMAIL_REGEX.match(tag_emailaddress):
                                email_user_address = tag_emailaddress
                                validuseremailaddress = True
                                break
                    if not validuseremailaddress:
                        users_list_email_tag_invalid.append(username)
                        if  EMAIL_USER_CONFIG["emailaddressconfig"]["reportmissingtag"]:
                            send_invaliduseremailaddress_email(EMAIL_ADMIN_TO, username, EMAIL_USER_CONFIG["emailaddressconfig"]["tagname"])

            except Exception:
                pass

        access_keys = client.list_access_keys(UserName=username)['AccessKeyMetadata']
        for access_key in access_keys:
            access_key_id = access_key['AccessKeyId']

            masked_access_key_id = mask_access_key(access_key_id)

            existing_key_status = access_key['Status']

            key_created_date = access_key['CreateDate']

            age = key_age(key_created_date)

            # we only need to examine the currently Active and about to expire keys
            if existing_key_status == "Inactive":
                key_state = 'key is already in an INACTIVE state'
                key_info = {'accesskeyid': masked_access_key_id, 'age': age, 'state': key_state, 'changed': False}
                user_keys.append(key_info)
                continue

            key_state = ''
            key_state_changed = False
            if age < FIRST_WARNING_NUM_DAYS:
                key_state = KEY_YOUNG_MESSAGE
            elif age == FIRST_WARNING_NUM_DAYS:
                key_state = FIRST_WARNING_MESSAGE
                users_list_first_warning.append(username)
                if email_user_enabled and email_user_address:                    
                    send_user_email(email_user_address, masked_access_key_id, FIRST_WARNING_MESSAGE)
            elif age == LAST_WARNING_NUM_DAYS:
                key_state = LAST_WARNING_MESSAGE
                users_list_last_warning.append(username)
                if email_user_enabled and email_user_address:
                    send_user_email(email_user_address, masked_access_key_id, LAST_WARNING_MESSAGE)
            elif age >= KEY_MAX_AGE_IN_DAYS:
                key_state = KEY_EXPIRED_MESSAGE
                users_list_keys_deactivated.append(username)
                client.update_access_key(UserName=username, AccessKeyId=access_key_id, Status=KEY_STATE_INACTIVE)
                if email_user_enabled and email_user_address:
                    send_user_email(email_user_address, masked_access_key_id, KEY_EXPIRED_MESSAGE)
                
                if EMAIL_ADMIN:
                    send_deactivate_email(EMAIL_ADMIN_TO, username, age, masked_access_key_id)
                
                key_state_changed = True
                                
            key_info = {'accesskeyid': masked_access_key_id, 'age': age, 'state': key_state, 'changed': key_state_changed}
            user_keys.append(key_info)

        users_report.append({'userid': userindex, 'username': username, 'keys': user_keys})

    finished = str(datetime.now())
    deactivated_report = {'reportdate': finished, 'users': users_report}

    if EMAIL_ADMIN:
        send_completion_email(EMAIL_ADMIN_TO, finished, deactivated_report)

    print(f'List of usernames notified with first warning: {users_list_first_warning}')
    print(f'List of usernames notified with last warning: {users_list_last_warning}')
    print(f'List of usernames whose keys were deactivated today: {users_list_keys_deactivated}')
    print(f'List of usernames who dont have a valid email tag: {users_list_email_tag_invalid}')

    print('*****************************')
    print(f'Completed (v{BUILD_VERSION}): {finished}')
    print('*****************************')
    return deactivated_report

#if __name__ == "__main__":
#    event = 1
#    context = 1
#    lambda_handler(event, context)
