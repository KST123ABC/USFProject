import osquery, getpass
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

    # call to get logged in users
    users_list = logged_in_users(instance)
    # call to parse users_list
    suspicious_users = analyze_users(users_list)
    # print suspicious users
    print("-----SUSPICIOUS LOGGED-IN USERS-----")
    print_dict(suspicious_users)

    # examine WiFi networks
    print("-----RETRIEVING OPEN WIFI NETWORKS-----")
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
        print("-----OS is Mac-----")

        # dump binaries with SUID bit set
        print("-----RETRIEVING BINARIES RUNNING WITH ADMIN PRIVILEGES-----")
        adminFiles = getSUID(instance)
        if adminFiles != []:
            # adivce to normal user
            print("Please remove the setuid and setguid bits from the following"
                " files. \nFor each file, run `sudo chmod -s pathToFile` where "
                "`pathToFile` is the path provided below.")
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
                "then repeat it by running `crontab -e`.")
            print_dict(crontab)
        else:
            print("No malicious crontab entries found.")

    elif os_type == 'Windows':
        # run windows specific functions
        print("-----OS is Windows-----")

    else:
        # run linux specific function
        print("-----OS is Linux based-----")

        # dump binaries with SUID bit set
        print("-----RETRIEVING BINARIES RUNNING WITH ADMIN PRIVILEGES-----")
        adminFiles = getSUID(instance)
        if adminFiles != []:
            # adivce to normal user
            print("Please remove the setuid and setguid bits from the following"
                " files. \nFor each file, run `sudo chmod -s pathToFile` where "
                "`pathToFile` is the path provided below.")
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
                "then repeat it by running `crontab -e`.")
            print_dict(crontab)
        else:
            print("No malicious crontab entries found.")
