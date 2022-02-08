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

# import os
# from unittest import mock

import pytest

from tests.test_utils.db import clear_db_dags, clear_db_import_errors, clear_db_serialized_dags
from tests.test_utils.www import check_content_in_response, check_content_not_in_response, client_with_login


def clean_db():
    clear_db_dags()
    clear_db_import_errors()
    clear_db_serialized_dags()


@pytest.fixture(autouse=True)
def setup():
    clean_db()
    yield
    clean_db()


def test_home(admin_client):
    resp = admin_client.get('home', follow_redirects=True)
    check_content_not_in_response('Sign In - Airflow', resp)
    check_content_in_response('DAGs - Airflow', resp)
