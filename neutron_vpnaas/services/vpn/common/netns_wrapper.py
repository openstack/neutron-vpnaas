# Copyright (c) 2015 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import configparser as ConfigParser
import errno
import os
import sys

from eventlet.green import subprocess
from neutron.common import config
from neutron.common import utils
from neutron_lib.utils import helpers
from oslo_config import cfg
from oslo_log import log as logging
from oslo_rootwrap import wrapper

from neutron_vpnaas._i18n import _

LOG = logging.getLogger(__name__)


def setup_conf():
    cli_opts = [
        cfg.DictOpt('mount_paths',
                    required=True,
                    help=_('Dict of paths to bind-mount (source:target) '
                           'prior to launch subprocess.')),
        cfg.ListOpt(
            'cmd',
            required=True,
            help=_('Command line to execute as a subprocess '
                   'provided as comma-separated list of arguments.')),
        cfg.StrOpt('rootwrap_config', default='/etc/neutron/rootwrap.conf',
                   help=_('Rootwrap configuration file.')),
    ]
    conf = cfg.CONF
    conf.register_cli_opts(cli_opts)
    return conf


def execute(cmd):
    if not cmd:
        return
    cmd = list(map(str, cmd))
    LOG.debug("Running command: %s", cmd)
    env = os.environ.copy()
    obj = utils.subprocess_popen(cmd, shell=False,
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 env=env)

    _stdout, _stderr = obj.communicate()
    _stdout = helpers.safe_decode_utf8(_stdout)
    _stderr = helpers.safe_decode_utf8(_stderr)
    msg = ('Command: %(cmd)s Exit code: %(returncode)s '
           'Stdout: %(stdout)s Stderr: %(stderr)s' %
           {'cmd': cmd,
            'returncode': obj.returncode,
            'stdout': _stdout,
            'stderr': _stderr})
    LOG.debug(msg)
    obj.stdin.close()
    # Pass the output to calling process
    sys.stdout.write(msg)
    sys.stdout.flush()
    return obj.returncode


def filter_command(command, rootwrap_config):
    # Load rootwrap configuration
    try:
        rawconfig = ConfigParser.RawConfigParser()
        rawconfig.read(rootwrap_config)
        rw_config = wrapper.RootwrapConfig(rawconfig)
    except ValueError as exc:
        LOG.error('Incorrect value in %(config)s: %(exc)s',
                  {'config': rootwrap_config, 'exc': exc})
        sys.exit(errno.EINVAL)
    except ConfigParser.Error:
        LOG.error('Incorrect configuration file: %(config)s',
                  {'config': rootwrap_config})
        sys.exit(errno.EINVAL)

    # Check if command matches any of the loaded filters
    filters = wrapper.load_filters(rw_config.filters_path)
    try:
        wrapper.match_filter(filters, command, exec_dirs=rw_config.exec_dirs)
    except wrapper.FilterMatchNotExecutable as exc:
        LOG.error('Command %(command)s is not executable: '
                  '%(path)s (filter match = %(name)s)',
                  {'command': command,
                   'path': exc.match.exec_path,
                   'name': exc.match.name})
        sys.exit(errno.EINVAL)
    except wrapper.NoFilterMatched:
        LOG.error('Unauthorized command: %(cmd)s (no filter matched)',
                  {'cmd': command})
        sys.exit(errno.EPERM)


def execute_with_mount():
    config.register_common_config_options()
    conf = setup_conf()
    conf()
    config.setup_logging()
    if not conf.cmd:
        LOG.error('No command provided, exiting')
        return errno.EINVAL

    if not conf.mount_paths:
        LOG.error('No mount path provided, exiting')
        return errno.EINVAL

    # Both sudoers and rootwrap.conf will not exist in the directory /etc
    # after bind-mount, so we can't use utils.execute(conf.cmd,
    # run_as_root=True). That's why we have to check here if cmd matches
    # CommandFilter
    filter_command(conf.cmd, conf.rootwrap_config)

    # Make sure the process is running in net namespace invoked by ip
    # netns exec(/proc/[pid]/ns/net) which is since Linux 3.0,
    # as we can't check mount namespace(/proc/[pid]/ns/mnt)
    # which is since Linux 3.8. For more detail please refer the link
    # http://man7.org/linux/man-pages/man7/namespaces.7.html
    if os.path.samefile(os.path.join('/proc/1/ns/net'),
                        os.path.join('/proc', str(os.getpid()), 'ns/net')):
        LOG.error('Cannot run without netns, exiting')
        return errno.EINVAL

    for path, new_path in conf.mount_paths.items():
        if not os.path.isdir(new_path):
            # Sometimes all directories are not ready
            LOG.debug('%s is not directory', new_path)
            continue
        if os.path.isdir(path) and os.path.isabs(path):
            return_code = execute(['mount', '--bind', new_path, path])
            if return_code == 0:
                LOG.info('%(new_path)s has been '
                         'bind-mounted in %(path)s',
                         {'new_path': new_path, 'path': path})
            else:
                LOG.error('Failed to bind-mount '
                          '%(new_path)s in %(path)s',
                          {'new_path': new_path, 'path': path})
    return execute(conf.cmd)


def main():
    sys.exit(execute_with_mount())


if __name__ == "__main__":
    main()
