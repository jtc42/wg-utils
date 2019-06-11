import subprocess
import os
from jinja2 import Environment, FileSystemLoader, select_autoescape
from ipaddress import ip_network, ip_address, IPv4Address, IPv6Address

HERE = os.path.dirname(os.path.realpath(__file__))

jfile_env = Environment(
    loader=FileSystemLoader(searchpath=os.path.join(HERE, 'templates'))
)

def list_ifaces():
    r = subprocess.run(["wg", "show", "interfaces"], stdout=subprocess.PIPE)
    assert r.returncode==0
    return r.stdout.decode().split()

def valid_iface(iface: str):
    if iface in list_ifaces():
        return True
    else:
        return False

def get_keys():
    r = subprocess.run(["wg", "genkey"], stdout=subprocess.PIPE)
    assert r.returncode==0
    privkeyraw = r.stdout
    privkey = privkeyraw.decode().strip()

    p = subprocess.Popen(
        ["wg", "pubkey"], 
        stdout=subprocess.PIPE, 
        stdin=subprocess.PIPE, 
        stderr=subprocess.STDOUT
    )

    pubkeyraw = p.communicate(input=privkeyraw)[0]
    pubkey = pubkeyraw.decode().strip()
    
    return (privkey, pubkey)

def get_wg_ip(iface: str, ipv6: bool=False):
    r = subprocess.run(["/sbin/ip", "address", "show", iface], stdout=subprocess.PIPE)
    assert r.returncode==0
    out = r.stdout.decode()
    
    if ipv6:
        prefix = 'inet6 '
    else:
        prefix = 'inet '

    ip = None

    for line in out.splitlines():
        line = line.strip()
        if line.startswith(prefix):
            ip = line.split(prefix)[1].split("scope ")[0].strip()
    
    return ip

def show_iface(iface: str):
    r = subprocess.run(["wg", "show", iface], stdout=subprocess.PIPE)
    assert r.returncode==0
    return r.stdout.decode().strip()

def get_network(iface: str, ipv6: bool=False):
    wg_ip = get_wg_ip(iface, ipv6=ipv6)

    if wg_ip:
        network = ip_network(wg_ip, strict=False)
        return network
    else:
        return None

def get_used_ips(iface: str):
    details = show_iface(iface)

    used_ranges = []

    prefix = "allowed ips:"
    for line in details.splitlines():
        line = line.strip()
        if line.startswith(prefix):
            # Turn into a comma separated list of IP ranges
            line = line.split(prefix)[1].strip()
            ips = line.split(', ')
            used_ranges.extend(ips)

    used_ips = []

    for wg_ip_range in [get_wg_ip(iface, ipv6=False), get_wg_ip(iface, ipv6=True)]:
        if wg_ip_range:
            ip_str = wg_ip_range.split('/')[0]
            ip = ip_address(ip_str)
            used_ips.append(ip)
    
    for wg_network in [get_network(iface, ipv6=False), get_network(iface, ipv6=True)]:
        if wg_network:
            used_ips.append(wg_network.network_address)

    for r in used_ranges:
        network = ip_network(r, strict=False)
        used_ips.append(network.network_address)
        used_ips.extend(list(network.hosts()))

    return used_ips
    
def get_next_ip(iface: str, ipv6: bool=False):
    network = get_network(iface, ipv6=ipv6)
    reserved = get_used_ips(iface)

    hosts_iterator = (host for host in network.hosts() if host not in reserved)

    return next(hosts_iterator)

def peer_stanza(hostname: str, ip: str, pubkey: str):
    template = jfile_env.get_template('peer_stanza')
    return template.render(
        hostname=hostname,
        ip=ip,
        pubkey=pubkey
    )

def client_config(iface: str, hostname: str, ip: str, privkey: str, serverendpoint: str, serverallowedips: str):
    r = subprocess.run(["wg", "show", iface, "public-key"], stdout=subprocess.PIPE)
    assert r.returncode==0

    hostpubkeyraw = r.stdout
    hostpubkey = hostpubkeyraw.decode().strip()

    template = jfile_env.get_template('client_config')
    return template.render(
        hostname=hostname,
        ip=ip,
        hostpubkey=hostpubkey,
        privkey=privkey,
        serverendpoint=serverendpoint,
        serverallowedips=serverallowedips
    )

def add_peer(iface: str, ip: str, pubkey: str):
    r = subprocess.run(["wg", "set", iface, "peer", pubkey, "allowed-ips", ip], stdout=subprocess.PIPE)
    print(r.stdout.decode().strip())
    return r