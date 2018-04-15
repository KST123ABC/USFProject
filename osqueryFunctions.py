import time

# This file contains all of the functions that deal with the database and
# manipulate data.

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
    users_list_dict = instance.client.query("select * from logged_in_users"
        "").response
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
    networks = inst.client.query("select ssid, network_name, last_connected from wifi_networks"
        " where security_type like 'Open' order by last_connected desc").response
    for wifi in networks:
        timestamp = int(wifi['last_connected'])
        wifi['last_connected'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))
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
    os_name = inst.client.query("select name from os_version"
        "").response[0]['name']
    if mac in os_name:
        return mac
    elif win in os_name:
        return win
    else:
        return linux

# Retrieve list of crontab entries and check if they exist in the
# crontab_defaults file. If they exist in there, they have been deemed to not be
# malicious.
# inst: the osquery instance that has been spawned
# return: list of malicious crontab entries (the command)
# WARNING: CAN ONLY BE RUN ON *NIX BASED SYSTEMS
def getCron(inst):
    crontab = inst.client.query("select command from crontab").response
    with open('crontab_defaults.txt', 'r') as f:
        goodCron = f.read().splitlines()
    badCron =[]

    for cronEntry in crontab:
        if cron not in goodCron:
            badCron.append(cron)
    return badCron

# Retrieve list of ports that are listening on the host.
# inst: the osquery instance that has been spawned
# return: list of listening ports (pid, port, address)
def getPorts(inst):
    ports = inst.client.query("select pid, port, address from listening_ports"
        "").response

    badPorts = []
    for port in ports:
        # currently we are ignoring port 0
        if port['port'] != '0':
            badPorts.append(port)
    return badPorts
