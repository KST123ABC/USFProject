import osquery, getpass, time
from osqueryFunctions import *


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

if __name__ == "__main__":
    # Spawn an osquery process using an ephemeral extension socket.
    instance = osquery.SpawnInstance()
    instance.open()

    # Issues queries

    # call to get current time on machine
    time = timestamp(instance)
    # print time
    print("\n*****Current time: " + time + "*****\n")

    # print system info
    info = getinfo(instance)
    print("-----SYSTEM INFO-----")
    print_dict(info)

    # call to get logged in users
    users_list = logged_in_users(instance)
    # call to parse users_list, [0] = active, [1] = dead users
    actDeadUsers = analyze_users(users_list)
    # print active users
    print("-----ACTIVE LOGGED-IN USERS-----")
    print("If any of these users shouldn't be here, simply run `sudo kill pid`"
        " and this will end the user's session.\n")
    if len(actDeadUsers[0]) > 0:
        print_dict(actDeadUsers[0])
    else:
        print("No active users.\n")
    # print dead users
    print("-----DEAD LOGGED-IN USERS-----")
    if len(actDeadUsers[1]) > 0:
        print_dict(actDeadUsers[1])
    else:
        print("No dead users.\n")

    # examine WiFi networks
    print("-----RETRIEVING OPEN WIFI NETWORKS-----")
    print("Be careful with what networks you connect to. All of these are \n"
        "unprotected networks where anyone can join them and see your \n"
        "traffic. If you are not using any of these, please remove them from \n"
        "the WiFi menu.\n")
    wifi_dict = getWiFi(instance)
    print_dict(wifi_dict)

    # dump listening ports
    print("-----RETRIEVING LISTENING PORTS-----")
    print_dict(getPorts(instance))

    # determine OS info to run OS specific commands
    os_type = getOS(instance)
    if os_type == 'Mac':
        # run mac specific functions
        # maybe list installed homebrew packages

        #print("-----OS is Mac-----\n")

        # dump binaries with SUID bit set
        print("-----RETRIEVING BINARIES RUNNING WITH ADMIN PRIVILEGES-----")
        adminFiles = getSUID(instance)
        if adminFiles != []:
            # adivce to normal user
            print("Please remove the setuid and setguid bits from the following"
                " files. \nFor each file, run `sudo chmod -s pathToFile` where "
                "`pathToFile` is the path provided below.\n")
            print_dict(adminFiles)
        else:
            print("No malicious binaries found with admin privileges.")

        # dump cron
        print("-----RETRIEVING CRONTAB ENTRIES-----")
        crontab = getCron(instance)
        if crontab != []:
            # adivce to normal user
            print("Please remove the following from your crontab. \nTo edit "
                "crontab, run `sudo crontab -e`, remove the offending line and "
                "then repeat it by running `crontab -e`.\n")
            print_dict(crontab)
        else:
            print("No malicious crontab entries found.\n\n")

        # get firewall status
        print("-----GETTING FIREWALL STATUS-----")
        if not getFirewall(instance):
            print("Your firewall is disabled. Go to 'System Preferences' then"
                "'Security & Privacy'. Click the lock in the bottom corner, "
                "then turn on your firewall.\n")
        else:
            print("Your firewall is enabled.\n")

    elif os_type == 'Windows':
        # run windows specific functions
        print("-----OS is Windows-----\n")

    else:
        # run linux specific function
        #print("-----OS is Linux based-----\n")

        # dump binaries with SUID bit set
        print("-----RETRIEVING BINARIES RUNNING WITH ADMIN PRIVILEGES-----")
        adminFiles = getSUID(instance)
        if adminFiles != []:
            # adivce to normal user
            print("Please remove the setuid and setguid bits from the following"
                " files. \nFor each file, run `sudo chmod -s pathToFile` where "
                "`pathToFile` is the path provided below.\n")
            print_dict(adminFiles)
        else:
            print("No malicious binaries found with admin privileges.")

        # dump cron
        print("-----RETRIEVING CRONTAB ENTRIES-----")
        crontab = getCron(instance)
        if crontab != []:
            # adivce to normal user
            print("Please remove the following from your crontab. \nTo edit "
                "crontab, run `sudo crontab -e`, remove the offending line and "
                "then repeat it by running `crontab -e`.\n")
            print_dict(crontab)
        else:
            print("No malicious crontab entries found.")
