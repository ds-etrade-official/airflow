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

import re

import pendulum
from flask import Blueprint
from openapi_core.contrib.flask.decorators import FlaskOpenAPIViewDecorator

api_blueprint = Blueprint('api', __name__, url_prefix='/api/v1')


class RFC3339Date:
    RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:[+-]\d{2}:\d{2}|Z)$")

    def validate(self, value) -> bool:
        return bool(self.RE.match(value))

    def unmarshal(self, value):
        return pendulum.parse(value)


class AirflowAPIViewDecorator(FlaskOpenAPIViewDecorator):
    def _handle_request_view(self, request_result, view, *args, **kwargs):
        for key, val in request_result.parameters.query.items():
            kwargs[key] = val
        __import__('pdb').set_trace()

        return super()._handle_request_view(request_result, view, *args, **kwargs)


def _get_decorator():
    from pathlib import Path

    import yaml
    from openapi_core import create_spec
    from openapi_core.contrib.flask.handlers import FlaskOpenAPIErrorsHandler
    from openapi_core.contrib.flask.providers import FlaskRequestProvider
    from openapi_core.contrib.flask.requests import FlaskOpenAPIRequestFactory
    from openapi_core.contrib.flask.responses import FlaskOpenAPIResponseFactory
    from openapi_core.validation.request.validators import RequestValidator
    from openapi_core.validation.response.validators import ResponseValidator

    custom_formatters = {
        'datetime': RFC3339Date(),
    }

    with (Path(__file__).parent.parent / 'openapi' / 'v1.yaml').open() as f:
        spec = create_spec(yaml.safe_load(f))

        request_validator = RequestValidator(spec, custom_formatters=custom_formatters)
        response_validator = ResponseValidator(spec, custom_formatters=custom_formatters)

        return AirflowAPIViewDecorator(
            request_validator=request_validator,
            response_validator=response_validator,
            request_factory=FlaskOpenAPIRequestFactory,
            response_factory=FlaskOpenAPIResponseFactory,
            request_provider=FlaskRequestProvider,
            openapi_errors_handler=FlaskOpenAPIErrorsHandler,
        )


def __getattr__(name):
    if name == 'openapi':
        return _get_decorator()
    raise AttributeError(name)


def init_blueprint():
    from airflow.api_connexion.endpoints import config_endpoint, connection_endpoint, health_endpoint  # noqa

    return api_blueprint
