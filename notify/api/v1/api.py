# Copyright 2016: Mirantis Inc.
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

import logging

import jsonschema
import flask

from notify import config
from notify.drivers.salesforce import salesforce

LOG = logging.getLogger("api")
LOG.setLevel(config.get_config().get("logging", {}).get("level", "INFO"))

notify_backends_config = config.get_config()['notify_backends']
sfdc_config = notify_backends_config['sf']['salesforce']['properties']


sfdc_oauth2 = salesforce.OAuth2(
    client_id=sfdc_config['client_id'],
    client_secret=sfdc_config['client_secret'],
    username=sfdc_config['username'],
    password=sfdc_config['password'],
    auth_url=sfdc_config['auth_url'],
    organizationId=sfdc_config['organization_id'])

sfdc_client = salesforce.Client(sfdc_oauth2)

bp = flask.Blueprint("alert", __name__)


@bp.route("/alert", methods=["POST"])
def send_alert():
    content = flask.request.get_json(force=True)
    if salesforce.validate_alert_data(alert=content):
        salesforce.send_to_sfdc(alert=content,
                                sfdc_client=sfdc_client,
                                environment=sfdc_config['environment'])

        return flask.jsonify({})
    else:
        return flask.jsonify({"errors": ["Incorrect data"]}), 409
    


def get_blueprints():
    return [["", bp]]
