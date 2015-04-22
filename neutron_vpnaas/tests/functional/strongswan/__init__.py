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

import os


def load_tests(loader, tests, pattern):
    this_dir = os.path.dirname(__file__)
    strongswan_tests = loader.discover(start_dir=this_dir, pattern=pattern)
    tests.addTests(strongswan_tests)

    common_dir = os.path.join(this_dir, "../common")
    common_tests = loader.discover(start_dir=common_dir, pattern=pattern)
    tests.addTests(common_tests)
    return tests
