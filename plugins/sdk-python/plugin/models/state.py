from datetime import date, datetime  # noqa: F401

from typing import List, Dict  # noqa: F401

from plugin.models.base_model import Model
from plugin import util


class State(Model):
    """NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).

    Do not edit the class manually.
    """

    """
    allowed enum values
    """
    NOTREADY = 'NotReady'
    READY = 'Ready'
    RUNNING = 'Running'
    FAILED = 'Failed'
    DONE = 'Done'
    def __init__(self):  # noqa: E501
        """State - a model defined in OpenAPI

        """
        self.openapi_types = {
        }

        self.attribute_map = {
        }

    @classmethod
    def from_dict(cls, dikt) -> 'State':
        """Returns the dict as a model

        :param dikt: A dict.
        :type: dict
        :return: The State of this State.  # noqa: E501
        :rtype: State
        """
        return util.deserialize_model(dikt, cls)
