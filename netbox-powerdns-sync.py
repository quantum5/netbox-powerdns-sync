#!/usr/bin/env python3

import argparse
import base64
import hashlib
import ipaddress
import logging
import re
import sys
from collections import Counter, defaultdict

import powerdns
import pynetbox
from systemd.journal import JournalHandler

from config import DEFAULT_TTL, DRY_RUN, FORWARD_ZONES, MULTI_FORWARD_ZONES, REVERSE_ZONES
from config import NB_TOKEN, NB_URL, PDNS_API_URL, PDNS_KEY
from config import SOURCE_DEVICE, SOURCE_IP, SOURCE_VM, SSHFP_DEVICE, SSHFP_VM


def name_in_zone(dns_name, zone, multi):
    if multi:
        return dns_name == zone or dns_name.endswith(f'.{zone}')
    else:
        return zone == '.'.join(dns_name.split('.')[1:])


def make_canonical(zone):
    # return a zone in canonical form
    return f'{zone}.'


def netbox_ip_reverse(nb_ip):
    ip = re.sub('/[0-9]*', '', str(nb_ip))
    return make_canonical(ipaddress.ip_address(ip).reverse_pointer)


def get_host_ips_ip(nb, zone, multi=False):
    # return list of tuples for ip addresses
    host_ips = []

    # get IPs with DNS name ending in forward_zone from NetBox
    nb_ips = set(nb.ipam.ip_addresses.filter(
        dns_name__iew=zone,
        status=['active', 'dhcp', 'slaac'],
    ))

    nb_ips.update(nb.ipam.ip_addresses.filter(
        cf_dns_alias=zone,
        status=['active', 'dhcp', 'slaac'],
    ))

    name_to_ip = defaultdict(list)
    for nb_ip in nb_ips:
        name_to_ip[nb_ip.dns_name].append(nb_ip)
        for alias in (nb_ip.custom_fields.get('dns_alias') or '').split():
            name_to_ip[alias].append(nb_ip)

    pairs = [(dns_name, value) for dns_name, values in name_to_ip.items() for value in values]

    for dns_name, nb_ip in pairs:
        if not name_in_zone(dns_name, zone, multi):
            continue

        host_ips.append((
            make_canonical(dns_name),
            'AAAA' if nb_ip.family.value == 6 else 'A',
            frozenset([re.sub('/[0-9]*', '', str(nb_ip))]),
            make_canonical(zone),
            nb_ip.custom_fields.get('dns_ttl') or DEFAULT_TTL
        ))

    return host_ips


def get_host_ips_ip_reverse(nb, prefix, zone):
    # return list of reverse zone tuples for ip addresses
    host_ips = []

    # get IPs within the prefix from NetBox
    nb_ips = nb.ipam.ip_addresses.filter(
        parent=prefix,
        status=['active', 'dhcp', 'slaac']
    )

    # assemble list with tuples containing the canonical name, the record type
    # and the IP address without the subnet from NetBox IPs
    for nb_ip in nb_ips:
        dns_name = nb_ip.dns_name

        if SOURCE_VM and not dns_name and nb_ip.assigned_object and nb_ip.assigned_object.virtual_machine:
            dns_name = nb_ip.assigned_object.virtual_machine.display

        if not dns_name:
            continue

        host_ips.append((
            netbox_ip_reverse(nb_ip),
            'PTR',
            frozenset([make_canonical(dns_name)]),
            make_canonical(zone),
            DEFAULT_TTL
        ))

    return host_ips


def get_host_ips_device(nb, zone):
    # return list of tuples for devices
    # get devices with name ending in forward_zone from NetBox
    nb_devices = nb.dcim.devices.filter(
        name__iew=zone,
        status=['active', 'failed', 'offline', 'staged']
    )

    return get_host_ips_host(nb_devices, zone)


def get_host_ips_vm(nb, zone):
    # return list of tuples for VMs
    # get VMs with name ending in forward_zone from NetBox
    nb_vms = nb.virtualization.virtual_machines.filter(
        name__iew=zone,
        status=['active', 'failed', 'offline', 'staged']
    )

    return get_host_ips_host(nb_vms, zone)


def get_host_ips_host(nb_hosts, zone):
    # return list of tuples for hosts (NetBox devices/VMs)
    host_ips = []

    # assemble list with tuples containing the canonical name, the record
    # type and the IP addresses without the subnet of the device/vm
    for nb_host in nb_hosts:
        if nb_host.primary_ip4 and not nb_host.primary_ip4.dns_name:
            host_ips.append((
                make_canonical(nb_host.name),
                'A',
                frozenset({re.sub('/[0-9]*', '', str(nb_host.primary_ip4))}),
                make_canonical(zone),
                DEFAULT_TTL
            ))

        if nb_host.primary_ip6 and not nb_host.primary_ip6.dns_name:
            host_ips.append((
                make_canonical(nb_host.name),
                'AAAA',
                frozenset([re.sub('/[0-9]*', '', str(nb_host.primary_ip6))]),
                make_canonical(zone),
                DEFAULT_TTL
            ))

    return host_ips


SSHFP_ALGOS = {
    'ssh-rsa': 1,
    'ssh-dsa': 2,
    'ecdsa-sha2-nistp256': 3,
    'ssh-ed25519': 4,
    'ssh-ed448': 6,
}


def key_to_sshfp(line):
    algo, pubkey, *_ = line.split()
    digest = hashlib.sha256(base64.b64decode(pubkey.encode('ascii'))).hexdigest()
    return f'{SSHFP_ALGOS[algo]} 2 {digest}'


def get_sshfp_hosts(nb_hosts, zone, multi=False):
    sshfps = []

    for nb_host in nb_hosts:
        sshfp = nb_host.custom_fields.get('sshfp')
        if not sshfp or not name_in_zone(nb_host.name, zone, multi):
            continue

        sshfps.append((
            make_canonical(nb_host.name),
            'SSHFP',
            frozenset([key_to_sshfp(key) for key in sshfp.splitlines()]),
            make_canonical(zone),
            DEFAULT_TTL,
        ))

    return sshfps


def get_sshfp_devices(nb, zone, multi=False):
    nb_devs = nb.dcim.devices.filter(
        name__iew=zone,
        status=['active', 'failed', 'offline', 'staged']
    )

    return get_sshfp_hosts(nb_devs, zone, multi=multi)


def get_sshfp_vms(nb, zone, multi=False):
    nb_vms = nb.virtualization.virtual_machines.filter(
        name__iew=zone,
        status=['active', 'failed', 'offline', 'staged']
    )

    return get_sshfp_hosts(nb_vms, zone, multi=multi)


def main():
    parser = argparse.ArgumentParser(
        description='Sync DNS name entries from NetBox to PowerDNS',
        epilog='''This script uses the REST API of NetBox to retriev
        IP addresses and their DNS name. It then syncs the DNS names
        to PowerDNS to create A, AAAA and PTR records.
        It does this for forward and reverse zones specified in the config
        file.
        ''')
    parser.add_argument('--dry_run', '-d', action='store_true',
                        help='Perform a dry run (make no changes to PowerDNS)')
    parser.add_argument('--loglevel', '-l', type=str, default='INFO',
                        choices=['WARNING', 'INFO', 'DEBUG', ''],
                        help='Log level for the console logger')
    parser.add_argument('--loglevel_journal', '-j', type=str, default='',
                        choices=['WARNING', 'INFO', ''],
                        help='Log level for the systemd journal logger')
    args = parser.parse_args()

    # merge dry_run directives from config and arguments
    dry_run = False
    if args.dry_run or DRY_RUN:
        dry_run = True

    logger = logging.getLogger(__name__)
    # set overall log level to debug to catch all
    logger.setLevel(logging.DEBUG)
    # loglevel for console logging
    if args.loglevel != '':
        handler = logging.StreamHandler()
        handler.setLevel(getattr(logging, args.loglevel))
        formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    # loglevel for journal logging
    if args.loglevel_journal != '':
        journal_handler = JournalHandler()
        journal_handler.setLevel(getattr(logging, args.loglevel_journal))
        logger.addHandler(journal_handler)

    nb = pynetbox.api(NB_URL, token=NB_TOKEN)

    pdns_api_client = powerdns.PDNSApiClient(api_endpoint=PDNS_API_URL,
                                             api_key=PDNS_KEY)
    pdns = powerdns.PDNSEndpoint(pdns_api_client).servers[0]

    nb_records = []
    pd_records = []

    for forward_zone in FORWARD_ZONES + MULTI_FORWARD_ZONES:
        multi = forward_zone in MULTI_FORWARD_ZONES

        # Source IP: Create domains based on DNS name attached to IPs
        if SOURCE_IP:
            nb_records += get_host_ips_ip(nb, forward_zone, multi=multi)
        # Source device: Create domains based on the name of devices
        if SOURCE_DEVICE:
            nb_records += get_host_ips_device(nb, forward_zone)
        # Source VM: Create domains based on the name of VMs
        if SOURCE_VM:
            nb_records += get_host_ips_vm(nb, forward_zone)

        if SSHFP_DEVICE:
            nb_records += get_sshfp_devices(nb, forward_zone, multi=multi)

        if SSHFP_VM:
            nb_records += get_sshfp_vms(nb, forward_zone, multi=multi)

        # get zone forward_zone_canonical form PowerDNS
        zone = pdns.get_zone(make_canonical(forward_zone))

        if zone is None:
            logger.critical(f'Zone {forward_zone} not found in PowerDNS. Skipping it.')
            continue

        # assemble list with tuples containing the canonical name, the record
        # type, the IP address and forward_zone_canonical without the subnet
        # from PowerDNS zone records with the
        # comment 'NetBox'
        for rrset in zone.records:
            for comment in rrset['comments']:
                if comment['content'] == 'NetBox':
                    pd_records.append((
                        rrset['name'],
                        rrset['type'],
                        frozenset([record['content'] for record in rrset['records']]),
                        make_canonical(forward_zone),
                        rrset['ttl']
                    ))

    for reverse_zone in REVERSE_ZONES:
        nb_records += get_host_ips_ip_reverse(nb, reverse_zone['prefix'],
                                              reverse_zone['zone'])

        # get reverse zone records form PowerDNS
        zone = pdns.get_zone(make_canonical(reverse_zone['zone']))

        if zone is None:
            logger.critical(f'Zone {reverse_zone["zone"]} not found in PowerDNS. Skipping it.')
            continue

        # assemble list with tuples containing the canonical name, the record
        # type, the IP address and forward_zone_canonical without the subnet
        # from PowerDNS zone records with the
        # comment 'NetBox'
        for rrset in zone.records:
            for comment in rrset['comments']:
                if comment['content'] == 'NetBox':
                    pd_records.append((
                        rrset['name'],
                        rrset['type'],
                        frozenset([record['content'] for record in rrset['records']]),
                        make_canonical(reverse_zone['zone']),
                        rrset['ttl']
                    ))

    # find duplicates in nb_records
    duplicate_records = [(name, rtype) for name, rtype, *_ in nb_records]
    duplicate_records = [duplicate for duplicate, amount in
                         Counter(duplicate_records).items() if amount > 1]
    for duplicate_record in duplicate_records:
        logger.critical(f'''Detected duplicate record from NetBox \
{duplicate_record[0]} of type {duplicate_record[1]}.
Not continuing execution. Please resolve the duplicate.''')
    if len(duplicate_records) > 0:
        sys.exit()

    # create set with tuples that have to be created
    # tuples from NetBox without tuples that already exists in PowerDNS
    to_create = set(nb_records) - set(pd_records)

    # create set with tuples that have to be deleted
    # tuples from PowerDNS without tuples that are documented in NetBox
    to_delete = set(pd_records) - set(nb_records)

    logger.info(f'{len(to_delete)} records to delete')
    for record in to_delete:
        logger.info(f'Will delete record {record}')

    logger.info(f'{len(to_create)} records to create')
    for record in to_create:
        logger.info(f'Will create record {record}')

    if dry_run:
        logger.info('Skipping Create/Delete due to Dry Run')
        sys.exit()

    affected_zones = set()

    for name, rtype, records, zone, ttl in to_delete:
        logger.info(f'Now deleting {(name, rtype, records, zone, ttl)}')
        affected_zones.add(zone)
        zone = pdns.get_zone(zone)
        zone.delete_records([
            powerdns.RRSet(name, rtype, records, comments=[powerdns.Comment('NetBox')])
        ])

    for name, rtype, records, zone, ttl in to_create:
        logger.info(f'Now creating {(name, rtype, records, zone, ttl)}')
        affected_zones.add(zone)
        zone = pdns.get_zone(zone)
        zone.create_records([
            powerdns.RRSet(name, rtype, records, ttl=ttl, comments=[powerdns.Comment('NetBox')])
        ])

    for zone in affected_zones:
        logger.info(f'Now rectifying {zone}')
        zone = pdns.get_zone(zone)
        zone._put(zone.url + '/rectify')


if __name__ == '__main__':
    main()
