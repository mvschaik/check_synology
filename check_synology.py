#!/usr/bin/env python3

import argparse
import logging
import math
import re
import sys

import easysnmp
import nagiosplugin
from nagiosplugin import Check, Metric

AUTHOR = "Frederic Werner"
VERSION = 0.1
_log = logging.getLogger('nagiosplugin')


DISK_STATUS = {
    1: "Normal",
    2: "Initialized",
    3: "NotInitialized",
    4: "SystemPartitionFailed",
    5: "Crashed"
}

UPDATE_STATUS = {
    1: "Available",
    2: "Unavailable",
    3: "Connecting",
    4: "Disconnected",
    5: "Others"
}

STATUS_STATUS = {
    1: "Normal",
    2: "Failed"
}


class Synology(nagiosplugin.Resource):
    def __init__(self, hostname, user_name, auth_key, priv_key):
        self._session = easysnmp.Session(
            hostname=hostname,
            version=3,
            security_level="auth_with_privacy",
            security_username=user_name,
            auth_password=auth_key,
            auth_protocol="MD5",
            privacy_password=priv_key,
            privacy_protocol="AES128")

    def snmpget(self, oid):
        try:
            res = self._session.get(oid)
            return res.value
        except easysnmp.EasySNMPError as e:
            _log.error(e)
            return None

    def snmpwalk(self, oid):
        """
        Walk the given OID and return all child OIDs as a list of
        tuples of OID and value.
        """
        res = []
        try:
            res = self._session.walk(oid)
        except easysnmp.EasySNMPError as e:
            _log.error(e)
        return res


class Load(Synology):
    def probe(self):
        load1 = float(self.snmpget('1.3.6.1.4.1.2021.10.1.5.1'))/100
        load5 = float(self.snmpget('1.3.6.1.4.1.2021.10.1.5.2'))/100
        load15 = float(self.snmpget('1.3.6.1.4.1.2021.10.1.5.3'))/100

        return [Metric('load1', load1, min=0, context='load'),
                Metric('load5', load5, min=0, context='default'),
                Metric('load15', load15, min=0, context='default')]


class LoadSummary(nagiosplugin.Summary):
    def ok(self, results):
        return 'load average: %s, %s, %s' % (
                results['load1'].metric,
                results['load5'].metric,
                results['load15'].metric)


class Memory(Synology):
    def probe(self):
        memory_total = float(self.snmpget('1.3.6.1.4.1.2021.4.5.0'))
        memory_unused = float(self.snmpget('1.3.6.1.4.1.2021.4.6.0'))
        memory_available = (
                memory_unused + float(self.snmpget('1.3.6.1.4.1.2021.4.15.0')))
        memory_percent = 100 / memory_total * memory_available

        return [Metric('memory_percent', memory_percent, uom='%',
                       min=0, max=100, context='memory'),
                Metric('memory_available', memory_available, uom='MB',
                       min=0, max=memory_total, context='default'),
                Metric('memory_unused', memory_unused, uom='MB',
                       min=0, max=memory_total, context='default'),
                Metric('memory_total', memory_total, context='null')]


class MemorySummary(nagiosplugin.Summary):
    def ok(self, result):
        return '%0.1f%% available (%0.1f MB out of %0.1f MB)' % \
            (result['memory_percent'].metric.value,
             result['memory_available'].metric.value,
             result['memory_total'].metric.value)


class Disk(Synology):
    def probe(self):
        self.disk_names = []

        for item in self.snmpwalk('1.3.6.1.4.1.6574.2.1.1.2'):
            i = item.oid.split('.')[-1]
            disk_name = item.value
            disk_name = disk_name.replace(" ", "")
            self.disk_names.append(disk_name)
            disk_status_nr = int(
                    self.snmpget('1.3.6.1.4.1.6574.2.1.1.5.' + str(i)))
            disk_temp = float(
                    self.snmpget('1.3.6.1.4.1.6574.2.1.1.6.' + str(i)))

            yield Metric('status%s' % disk_name, disk_status_nr,
                         context='disk_status')
            yield Metric('temperature%s' % disk_name, disk_temp,
                         context='temp')


class DiskContext(nagiosplugin.Context):
    def evaluate(self, metric, resource):
        if metric.value in [4, 5]:
            return nagiosplugin.Critical
        return nagiosplugin.Ok


class DiskSummary(nagiosplugin.Summary):
    def ok(self, result):
        output = []
        for disk_name in result.first_significant.resource.disk_names:
            status = DISK_STATUS[result['status%s' % disk_name].metric.value]
            temp = result['temperature%s' % disk_name].metric.value
            output.append('%s: Status: %s, Temperature: %s C' % (
                    disk_name, status, temp))
        return ' - '.join(output)


class Storage(Synology):
    def probe(self):
        for item in self.snmpwalk('1.3.6.1.2.1.25.2.3.1.3'):
            i = item.oid.split('.')[-1]
            storage_name = item.value
            if re.match("/volume(?!.+/@docker.*)", storage_name):
                allocation_units = self.snmpget(
                        '1.3.6.1.2.1.25.2.3.1.4.' + str(i))
                size = self.snmpget(
                        '1.3.6.1.2.1.25.2.3.1.5.' + str(i))
                used = self.snmpget(
                        '1.3.6.1.2.1.25.2.3.1.6.' + str(i))

                storage_size = int(
                        (int(allocation_units) * int(size)) / 1000000000)
                storage_used = int(
                        (int(used) * int(allocation_units)) / 1000000000)
                storage_free = int(storage_size - storage_used)

                yield Metric(storage_name, storage_used,
                             min=0, max=storage_size, context='storage')


class StorageSummary(nagiosplugin.Summary):
    def ok(self, results):
        output = []
        for result in results:
            used = result.metric.value
            size = result.metric.max
            free = size - result.metric.value
            output.append(
                    'free space: %s %s GB (%s GB of %s GB used, %s%%)' %
                    (result.metric.name, free, used, size,
                     int(used * 100 / size)))

        return ' - '.join(output)


class Update(Synology):
    def probe(self):
        update_status_nr = int(self.snmpget('1.3.6.1.4.1.6574.1.5.4.0'))
        update_dsm_version = self.snmpget('1.3.6.1.4.1.6574.1.5.3.0')

        return [Metric('DSMUpdate', update_status_nr, context='update'),
                Metric('DSMVersion', update_dsm_version, context='null')]


class UpdateContext(nagiosplugin.Context):
    def evaluate(self, metric, resource):
        if metric.value == 1:
            return nagiosplugin.Warning
        if metric.value in [4, 5]:
            return nagiosplugin.Critical
        return nagiosplugin.Ok


class UpdateSummary(nagiosplugin.Summary):
    def ok(self, result):
        return 'DSM Version: %s, DSM Update: %s' % (
                result['DSMVersion'].metric.value,
                UPDATE_STATUS[result['DSMUpdate'].metric.value])


class Status(Synology):
    def probe(self):
        status_model = self.snmpget('1.3.6.1.4.1.6574.1.5.1.0')
        status_serial = self.snmpget('1.3.6.1.4.1.6574.1.5.2.0')
        status_temperature = float(self.snmpget('1.3.6.1.4.1.6574.1.2.0'))

        status_system = int(self.snmpget('1.3.6.1.4.1.6574.1.1.0'))
        status_system_fan = int(self.snmpget('1.3.6.1.4.1.6574.1.4.1.0'))
        status_cpu_fan = int(self.snmpget('1.3.6.1.4.1.6574.1.4.2.0'))
        status_power = int(self.snmpget('1.3.6.1.4.1.6574.1.3.0'))

        return [
                Metric('model', status_model, context='null'),
                Metric('serial', status_serial, context='null'),
                Metric('temperature', status_temperature, context='temp'),
                Metric('system', status_system, context='status'),
                Metric('system_fan', status_system_fan, context='status'),
                Metric('cpu_fan', status_cpu_fan, context='status'),
                Metric('power', status_power, context='status'),
                ]


class StatusContext(nagiosplugin.Context):
    def evaluate(self, metric, resource):
        if metric.value == 2:
            return nagiosplugin.Critical
        return nagiosplugin.Ok


class StatusSummary(nagiosplugin.Summary):
    def ok(self, result):
        return ('Model: %s, ' +
                'System Temperature: %s C, ' +
                'System Status: %s, ' +
                'System Fan: %s, ' +
                'CPU Fan: %s, ' +
                'Powersupply: %s') % (
                    result['model'].metric.value,
                    result['temperature'].metric.value,
                    STATUS_STATUS[result['system'].metric.value],
                    STATUS_STATUS[result['system_fan'].metric.value],
                    STATUS_STATUS[result['cpu_fan'].metric.value],
                    STATUS_STATUS[result['power'].metric.value])

    def problem(self, result):
        metric = result.first_significant.metric
        return '%s: %s' % (metric.name, STATUS_STATUS[metric.value])


@nagiosplugin.guarded
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("hostname", help="the hostname", type=str)
    parser.add_argument("username", help="the snmp user name", type=str)
    parser.add_argument("authkey", help="the auth key", type=str)
    parser.add_argument("privkey", help="the priv key", type=str)
    parser.add_argument("mode", help="the mode", type=str,
                        choices=["load", "memory", "disk", "storage",
                                 "update", "status"])
    parser.add_argument("-w", help="warning value for selected mode", type=int)
    parser.add_argument("-c", help="critical value for selected mode",
                        type=int)
    parser.add_argument('-v', '--verbose', action='count', default=0)
    args = parser.parse_args()

    warning = args.w
    critical = args.c

    check = None
    if args.mode == 'load':
        check = Check(
                Load(args.hostname, args.username, args.authkey, args.privkey),
                nagiosplugin.ScalarContext('load', warning, critical),
                LoadSummary())
    elif args.mode == 'memory':
        check = Check(
                Memory(args.hostname, args.username, args.authkey,
                       args.privkey),
                nagiosplugin.ScalarContext('memory', warning, critical),
                MemorySummary())
    elif args.mode == 'disk':
        check = Check(
                Disk(args.hostname, args.username, args.authkey, args.privkey),
                nagiosplugin.ScalarContext('temp', warning, critical),
                DiskContext('disk_status'),
                DiskSummary())
    elif args.mode == 'storage':
        check = Check(
                Storage(args.hostname, args.username, args.authkey,
                        args.privkey),
                nagiosplugin.ScalarContext('storage', warning, critical),
                StorageSummary())
    elif args.mode == 'update':
        check = Check(
                Update(args.hostname, args.username, args.authkey,
                       args.privkey),
                UpdateContext('update'),
                UpdateSummary())
    elif args.mode == 'status':
        check = Check(
                Status(args.hostname, args.username, args.authkey,
                       args.privkey),
                nagiosplugin.ScalarContext('temp', warning, critical),
                StatusContext('status'),
                StatusSummary())
    else:
        raise CheckError('Unknown mode', args.mode)
    check.main(args.verbose)


if __name__ == '__main__':
    main()
