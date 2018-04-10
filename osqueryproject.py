import osquery
import getpass

# Prints dictionary or list or both. Mostly used to print lists of
# dictionaries
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
    # users_dict = list of dictionaries, each entry of command 'who' would be
    # its own dict
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

# Retrieve WiFi networks that computer has connected to.
# inst: the osquery instance that has been spawned
# Return: list of networks (includes SSID, network name, security, last
# connected, auto login, disabled)
def getWiFi(inst):
    networks = inst.client.query("select ssid, network_name, security_type,"
        " last_connected, auto_login, disabled from wifi_networks").response
    return networks

# Retrieve list of binaries that have SUID bit set and then checks them against
# the file `suid_binaries.txt`. This file contains some/all of the binaries that
# have SUID set by default.
# GOAL: Look for programs that have been given SUID.
# inst: the osquery instance that has been spawned
# return: list of the suid binaries (includes path, user is it running as,
# group it is running as, permissions it has set)
# WARNING: CAN ONLY BE RUN ON *NIX BASED SYSTEMS
def getSUID(inst):
    binaries = inst.client.query("select * from suid_bin").response
    with open('suid_binaries.txt', 'r') as f:
        defBinaries = f.read().splitlines()

    badBinaries = []
    for binary in binaries:
        if binary['path'].split('/')[-1] not in defBinaries:
            badBinaries.append(binary)
    return badBinaries

# Determine what OS the system is running.
# Instance is the osquery instance that has been spawned.
# Return: Mac, Linux, or Windows
def getOS(inst):
    mac = 'Mac'
    linux = 'Linux'
    win = 'Windows'
    os_name = inst.client.query("select name from os_version").response[0]['name']
    if mac in os_name:
        return mac
    elif win in os_name:
        return win
    else:
        return linux

if __name__ == "__main__":
    # Spawn an osquery process using an ephemeral extension socket.
    instance = osquery.SpawnInstance()
    instance.open()

    # Issues queries

    # call to get current time on machine
    time = timestamp(instance)
    # print time
    print("-----Current time: " + time + "-----\n")

    # call to get logged in users
    users_list = logged_in_users(instance)
    # call to parse users_list
    suspicious_users = analyze_users(users_list)
    # print suspicious users
    print("-----Suspicious Logged-in Users-----")
    print_dict(suspicious_users)

    # examine WiFi networks
    print("-----RETRIEVING WIFI NETWORKS-----")
    print_dict(getWiFi(instance))

    # determine OS info to run OS specific commands
    os_type = getOS(instance)
    if os_type == 'Mac':
        # run mac specific functions
        # maybe list installed homebrew packages
        print("-----OS is Mac-----")
        # dump binaries with SUID bit set
        print("-----RETRIEVING BINARIES RUNNING WITH ADMIN PRIVILEGES-----")
        print_dict(getSUID(instance))
    elif os_type == 'Windows':
        # run windows specific functions
        print("-----OS is Windows-----")
    else:
        # run linux specific function
        print("-----OS is Linux based-----")
        # dump binaries with SUID bit set
        print("-----RETRIEVING BINARIES RUNNING WITH ADMIN PRIVILEGES-----")
        print_dict(getSUID(instance))
