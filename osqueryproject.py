import osquery
import getpass

# Prints dictionary or list or both. Mostly used to print lists of dictionaries
def print_dict(obj):
    if type(obj) == dict:
        for k, v in obj.items():
            print(k +": " + v)
    elif type(obj) == list:
        for v in obj:
            if hasattr(v, '__iter__'):
                print_dict(v)
            else:
                print(v)
    else:
        print(obj)
    print()

# Gets the current time of machine
# return: string timestamp
def timestamp(instance):
    # time_dict = dictionary of 1 item, just timestamp
    time_dict = instance.client.query("select timestamp from time").response[0]
    return time_dict['timestamp']


# Gets list of logged in users. Each logged in user is a dictionary.
# return: list of dictionaries
def logged_in_users(instance):
    # users_dict = list of dictionaries, each entry of command 'who' would be its own dict
    users_list_dict = instance.client.query("select * from logged_in_users").response
    return users_list_dict

# Parse list of logged in users
# return: list of dictionaries
def analyze_users(users):
    ''' # NOT WORKING
    current_user = getpass.getuser()
    # eliminate entries where the user is same as current user
    for user in users:
         if (user['user'] == 'lauraweintraub'):
             users.remove(user)
    '''
    return users


if __name__ == "__main__":
    # Spawn an osquery process using an ephemeral extension socket.
    instance = osquery.SpawnInstance()
    instance.open()  

    # Issues queries

    # call to get current time on machine
    time = timestamp(instance)
    # print time
    print("Current time: " + time + "\n")
    
    # call to get logged in users 
    users_list = logged_in_users(instance)
    
    # call to parse users_list
    suspicious_users = analyze_users(users_list)
    # print suspicious users
    print("Suspicious Logged-in Users:")
    print_dict(suspicious_users)
