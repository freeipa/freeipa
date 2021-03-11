#
# Copyright (C) 2021  FreeIPA Contributors see COPYING for license
#

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import division

from datetime import datetime
import logging
import re
from statistics import mean

from ipapython import admintool
from ipalib.facts import is_ipa_configured


TIME_RE = re.compile(
    r'\[(?P<date>.*)\] \[.*\].* \[pid \d+:tid \d+\] \[remote .*\] '
    r'ipa: DEBUG: \[jsonserver_session\] (?P<principal>\S+): '
    r'(?P<command>\S+)/1\(.*\): SUCCESS etime=(?P<etime>\d+)'
)
DATE_FORMAT = '%a %b %d %H:%M:%S.%f %Y'

logger = logging.getLogger(__name__)


class parselog(admintool.AdminTool):
    command_name = "parselog"

    usage = "%prog [options]"
    description = "Parse the Apache error log for performance data"

    def __init__(self, options, args):
        super(parselog, self).__init__(options, args)
        self.times = []
        self.since = None

    @classmethod
    def add_options(cls, parser):
        super(parselog, cls).add_options(parser, debug_option=True)
        parser.add_option(
            "--start-time",
            dest="start_time",
            action="store",
            default=None,
            help="time to begin analyzing logfile from",
        )

    def validate_options(self):
        super(parselog, self).validate_options(needs_root=True)

        if len(self.args) != 1:
            raise RuntimeError('command is required')

        if self.options.start_time:
            self.since = datetime.strptime(
                self.options.start_time,
                DATE_FORMAT
            )

    def run(self):
        super(parselog, self).run()

        if not is_ipa_configured():
            logger.error("IPA client is not configured on this system.")
            raise admintool.ScriptError()

        with open('/var/log/httpd/error_log', 'r') as f:
            data = f.read()

        matches = list(re.finditer(TIME_RE, data))

        command = self.args[0]

        for match in matches:
            if self.since:
                logtime = datetime.strptime(match.group('date'), DATE_FORMAT)
                if logtime < self.since:
                    continue
            if match.group('command') == command:
                self.times.append(float(match.group('etime')))

        if self.times:
            # Average dropping the min and max
            if len(self.times) > 5:
                meantime = mean(sorted(self.times)[1:-1])
                num = len(self.times) - 2
            else:
                meantime = mean(self.times)
                num = len(self.times)
            print(
                'Mean %s: %s of %d executions' % (
                    command,
                    meantime,
                    num)
            )
        else:
            print('No commands found')


if __name__ == '__main__':
    parselog.run_cli()
