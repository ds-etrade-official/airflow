#!/usr/bin/env bash
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
export PYTHON_MAJOR_MINOR_VERSION=${PYTHON_MAJOR_MINOR_VERSION:-3.6}

# shellcheck source=scripts/ci/libraries/_script_init.sh
. "$( dirname "${BASH_SOURCE[0]}" )/../libraries/_script_init.sh"

get_environment_for_builds_on_ci

echo "Verifying Files"
ls ./artifacts/constraints-*/
echo "Copying Constraints File"
cp -v ./artifacts/constraints-*/constraints*.txt repo/
echo "Copied Constraints File"
ls repo
cd repo || exit 1
cp constraints-3.6.txt constraints-3.7.txt
ls -a 
git status
git config --local user.email "ernest@astronomer.io"
git config --local user.name "ernest-kr"
git add constraints-*.txt
git diff --exit-code || git commit -v --all --message "Updating constraints. Build id:${CI_BUILD_ID} 
This update in constraints is automatically committed by the CI 'constraints-push' step based on
HEAD of '${CI_REF}' in '${CI_TARGET_REPO}'
with commit sha ${COMMIT_SHA}.

All tests passed in this build so we determined we can push the updated constraints.

See https://github.com/apache/airflow/blob/master/README.md#installing-from-pypi for details.
"
echo "Commit Done"
