from ipaddress import ip_address
from . import utils
import os

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

SERVER_ENDPOINT = os.environ.get('SERVER_ENDPOINT')
SERVER_EXTRA_ALLOWED_IPS = os.environ.get('SERVER_EXTRA_ALLOWED_IPS')

if not SERVER_ENDPOINT:
    print(bcolors.WARNING+"WARNING: No SERVER_ENDPOINT environment variable set. SERVER_ENDPOINT will be missing from client config files."+ bcolors.ENDC)
    SERVER_ENDPOINT = ":51820"
if not SERVER_EXTRA_ALLOWED_IPS:
    SERVER_EXTRA_ALLOWED_IPS = ""

def yes_or_no(question):
    answer = input(question + "(y/n): ").lower().strip()
    print("")
    while not(answer == "y" or answer == "yes" or \
    answer == "n" or answer == "no"):
        print("Input yes or no")
        answer = input(question + "(y/n):").lower().strip()
        print("")
    if answer[0] == "y":
        return True
    else:
        return False

def get_server_allowed_ips(iface: str):
    allowed_ips = []

    for wg_network in [utils.get_network(iface, ipv6=False), utils.get_network(iface, ipv6=True)]:
        if wg_network:
            allowed_ips.append(wg_network.compressed)
    
    extras = SERVER_EXTRA_ALLOWED_IPS.split(',')
    for ip in extras:
        ip = ip.strip()
        if ip:
            allowed_ips.append()
    
    return allowed_ips

def add(iface: str, hostname: str, verbose: bool=False):
    global SERVER_ENDPOINT
    # Get keys
    privkey, pubkey = utils.get_keys()

    # Generate server-side allowed IPs for the peer
    ipv4 = utils.get_next_ip(iface, ipv6=False)
    ipv6 = utils.get_next_ip(iface, ipv6=True)

    ip = "{}/32".format(ipv4)
    if ipv6:
        ip += ",{}/128".format(ipv6)
    
    # Use ip and args to generate a peer stanza
    peer_stanza = utils.peer_stanza(
        hostname=hostname,
        ip=ip,
        pubkey=pubkey
    )

    if verbose:
        print("\nPeer stanza:\n{}".format(peer_stanza))

    # Generate a client config
    allowed_ips_string = ','.join(get_server_allowed_ips(iface))
    client_config = utils.client_config(
        iface=iface,
        hostname=hostname,
        ip=ip,
        privkey=privkey,
        serverendpoint=SERVER_ENDPOINT,
        serverallowedips=allowed_ips_string
    )

    if verbose:
        print("\nClient config:\n{}".format(client_config))

    if yes_or_no(
        "Commit new peer {0}.wg with pubkey {1} to interface {2}?".format(
            hostname, 
            pubkey, 
            iface)):
        
        print("Adding peer to permanant configuration...")
        conf_path = "/etc/wireguard/{}.conf".format(iface)
        with open(conf_path, "a") as conf:
            conf.write(peer_stanza)
            conf.write("\n")
        print("Successfully written stanza to {}.".format(conf_path))

        if yes_or_no("Enable peer on the current interface?"):
            print("Adding peer to current interface...")
            utils.add_peer(iface, ip, pubkey)

        print("Client config:")
        print(client_config)

        if yes_or_no("Save client config to a file?"):
            client_file="{}-{}.conf".format(iface, hostname)
            with open(client_file, "w") as client:
                client.write(client_config)
                client.write("\n")
    
    else:
        print("Aborting")