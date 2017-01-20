# -*- coding: utf-8 -*-

# Copyright 2017 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import collections
import copy
import jsonschema
import pkg_resources
import yaml


def get_os_net_config_schema():
    """Returns the schema for os_net_config's config files."""
    schema_string = pkg_resources.resource_string(__name__, "schema.yaml")
    return yaml.load(schema_string)


def get_schema_for_defined_type(defined_type):
    """Returns the schema for a given defined type of the full schema."""
    full_schema = get_os_net_config_schema()
    type_schema = copy.deepcopy(full_schema["definitions"][defined_type])
    type_schema["$schema"] = full_schema["$schema"]
    type_schema["definitions"] = full_schema["definitions"]
    return type_schema


def validate_config(config, config_name="Config file"):
    """Validates a list of interface/bridge configurations against the schema.

    If validation fails, returns a list of validation error message strings.
    If validation succeeds, returns an empty list.
    `config_name` can be used to prefix errors with a more specific name.
    """
    return _validate_config(config, config_name,
                            get_os_net_config_schema(), True)


def _validate_config(config, config_name, schema, filter_errors):
    error_messages = []
    validator = jsonschema.Draft4Validator(schema)
    v_errors = validator.iter_errors(config)
    v_errors = sorted(v_errors, key=lambda e: e.path)
    for v_error in v_errors:
        error_message = _get_consistent_error_message(v_error)
        details = _get_detailed_errors(v_error, 1, v_error.schema_path,
                                       schema, filter_errors=filter_errors)

        config_path = '/'.join([str(x) for x in v_error.path])
        if details:
            error_messages.append(
                "{} failed schema validation at network_config/{}:\n"
                "    {}\n"
                "  Sub-schemas tested and not matching:\n"
                "  {}"
                .format(config_name, config_path, error_message,
                        '\n  '.join(details)))
        else:
            error_messages.append(
                "{} failed schema validation at network_config/{}:\n"
                "    {}"
                .format(config_name, config_path, error_message))
    return error_messages


def _get_consistent_error_message(error):
    """Returns error messages consistent across Python 2 and 3.

    jsonschema uses repr() to print its error messages, which means strings
    will render as "u'...'" in Python 2 and "'...'" in Python 3, making
    testing for error messages unnecessarily difficult.
    """

    if error.validator == 'type':
        return "'{}' is not of type '{}'".format(
               error.instance, error.validator_value)
    elif error.validator == 'enum':
        return "'{}' is not one of ['{}']".format(
               error.instance, "','".join(error.validator_value))
    elif error.validator == 'required':
        if error.message[0:2] == "u'":
            return error.message[1:]
    return error.message


def _get_detailed_errors(error, depth, absolute_schema_path, absolute_schema,
                         filter_errors=True):
    """Returns a list of error messages from all subschema validations.

    Recurses the error tree and adds one message per sub error. That list can
    get long, because jsonschema also tests the hypothesis that the provided
    network element type is wrong (e.g. "ovs_bridge" instead of "ovs_bond").
    Setting `filter_errors=True` assumes the type, if specified, is correct and
    therefore produces a much shorter list of more relevant results.
    """

    if not error.context:
        return []

    sub_errors = error.context
    if filter_errors:
        if (absolute_schema_path[-1] in ['oneOf', 'anyOf'] and
                isinstance(error.instance, collections.Mapping) and
                'type' in error.instance):
            found, index = _find_type_in_schema_list(
                error.validator_value, error.instance['type'])
            if found:
                sub_errors = [i for i in sub_errors if (
                              i.schema_path[0] == index)]

    details = []
    sub_errors = sorted(sub_errors, key=lambda e: e.schema_path)
    for sub_error in sub_errors:
        schema_path = collections.deque(absolute_schema_path)
        schema_path.extend(sub_error.schema_path)
        details.append("{} {}: {}".format(
            '-' * depth,
            _pretty_print_schema_path(schema_path, absolute_schema),
            _get_consistent_error_message(sub_error)))
        details.extend(_get_detailed_errors(
            sub_error, depth + 1, schema_path, absolute_schema,
            filter_errors))
    return details


def _find_type_in_schema_list(schemas, type_to_find):
    """Finds an object of a given type in an anyOf/oneOf array.

    Returns a tuple (`found`, `index`), where `found` indicates whether
    on object of type `type_to_find` was found in the `schemas` array.
    If so, `index` contains the object's position in the array.
    """
    for index, schema in enumerate(schemas):
        if not isinstance(schema, collections.Mapping):
            continue
        if ('$ref' in schema and
                schema['$ref'].split('/')[-1] == type_to_find):
            return (True, index)
        if ('properties' in schema and 'type' in schema['properties'] and
                schema['properties']['type'] == type_to_find):
            return (True, index)
    return (False, 0)


def _pretty_print_schema_path(absolute_schema_path, absolute_schema):
    """Returns a representation of the schema path that's easier to read.

    For example:
    >>> _pretty_print_schema_path("items/oneOf/0/properties/use_dhcp/oneOf/2")
    "items/oneOf/interface/use_dhcp/oneOf/param"
    """

    pretty_path = []
    current_path = []
    current_schema = absolute_schema
    for item in absolute_schema_path:
        if item not in ["properties"]:
            pretty_path.append(item)
        current_path.append(item)
        current_schema = current_schema[item]
        if (isinstance(current_schema, collections.Mapping) and
                '$ref' in current_schema):
            if (isinstance(pretty_path[-1], int) and
                    pretty_path[-2] in ['oneOf', 'anyOf']):
                pretty_path[-1] = current_schema['$ref'].split('/')[-1]
            current_path = current_schema['$ref'].split('/')
            current_schema = absolute_schema
            for i in current_path[1:]:
                current_schema = current_schema[i]
    return '/'.join([str(x) for x in pretty_path])
