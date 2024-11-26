"""
The MAC address module provides functionality to parse and validate MAC addresses in different
formats, such as IEEE 802 MAC-48, EUI-48, EUI-64, or a 20-octet format.
"""

from __future__ import annotations

import re
from typing import Any, Sequence

from pydantic import GetCoreSchemaHandler, GetJsonSchemaHandler
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import PydanticCustomError, core_schema

VIABLE_OCTET_COUNTS = 6, 8, 20
VALID_DELIMETERS = ':-.'
DELIM_SPACING = [
    (':', 1),
    ('-', 1),
    ('.', 2),
    ('',  1),
]
RHX = r'[0-9a-f]'
SIMPLE_PATTERNS = [
    delim.join('xx' * spacing for _ in range(octets//spacing))
    for octets in VIABLE_OCTET_COUNTS
    for delim, spacing in DELIM_SPACING
]
SIMPLE_REGEX_PATTERNS = [
    fr'^{RHX}{{{spacing*2}}}(?:{re.escape(delim)}{RHX}{{{spacing*2}}}){{{octets // spacing - 1}}}$'
    if delim else
    fr'^{RHX}{{{octets*2}}}$'
    for octets in VIABLE_OCTET_COUNTS
    for delim, spacing in DELIM_SPACING
]
REGEX_PATTERNS = [  # First oct/pair, optional delim, middle oct/pairs + delim, final oct/pair
    re.compile(r'^[\dA-F]{2}([:-]?)([\dA-F]{2}\1){4}[\dA-F]{2}$', re.IGNORECASE),
    re.compile(r'^[\dA-F]{2}([:-]?)([\dA-F]{2}\1){6}[\dA-F]{2}$', re.IGNORECASE),
    re.compile(r'^[\dA-F]{2}([:-]?)([\dA-F]{2}\1){18}[\dA-F]{2}$', re.IGNORECASE),
    re.compile(r'^[\dA-F]{4}(\.?)([\dA-F]{4}\1){1}[\dA-F]{4}$', re.IGNORECASE),
    re.compile(r'^[\dA-F]{4}(\.?)([\dA-F]{4}\1){2}[\dA-F]{4}$', re.IGNORECASE),
    re.compile(r'^[\dA-F]{4}(\.?)([\dA-F]{4}\1){8}[\dA-F]{4}$', re.IGNORECASE),
]


class MacAddress:
    """Represents a MAC address and provides methods for conversion, validation, and serialization.

    ```py
    from pydantic import BaseModel

    from pydantic_extra_types.mac_address import MacAddress


    class Network(BaseModel):
        mac_address: MacAddress


    network = Network(mac_address="00:00:5e:00:53:01")
    print(network)
    #> mac_address='00:00:5e:00:53:01'
    ```
    """
    def __init__(self, value):
        if isinstance(value, MacAddress):
            value = value._octets
        self._octets = self.validate_mac_address(value)

    def __int__(self) -> int:
        return int.from_bytes(self._octets, 'big')

    def __str__(self) -> str:
        return self._octets.hex(':')

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}("{self}")'

    def __eq__(self, other) -> bool:
        if isinstance(other, int):
            return int(self) == other
        elif isinstance(other, (str, MacAddress)):
            return str(self) == str(other)
        elif isinstance(other, Sequence):
            return self._octets == bytes(other)
        return False

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        core_schema: core_schema.CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> JsonSchemaValue:
        field_schema = {}
        field_schema.update(type='string', format='macaddress')
        return field_schema

    @classmethod
    def __get_pydantic_core_schema__(cls, source: type[Any], handler: GetCoreSchemaHandler) -> core_schema.CoreSchema:
        """
        Return a Pydantic CoreSchema with the MAC address validation.

        Args:
            source: The source type to be converted.
            handler: The handler to get the CoreSchema.

        Returns:
            A Pydantic CoreSchema with the MAC address validation.

        """
        return core_schema.no_info_plain_validator_function(
            cls._validate,
            serialization=core_schema.to_string_ser_schema(),
        )

    @classmethod
    def _validate(cls, __input_value: str | int | Sequence[int]) -> MacAddress:
        """
        Validate a MAC Address from the provided str value.

        Args:
            __input_value: The str value to be validated.
            _: The source type to be converted.

        Returns:
            str: The parsed MAC address.

        """
        if isinstance(__input_value, MacAddress):
            return __input_value
        return cls(__input_value)

    @staticmethod
    def validate_mac_address(value: str | int | Sequence[int]) -> bytes:
        """
        Validate a MAC Address from the provided byte value.
        """
        # Split by delimeter
        if isinstance(value, str):
            mac_match = None
            for pattern in REGEX_PATTERNS:
                mac_match = mac_match or pattern.match(value)

            if mac_match is None:
                raise PydanticCustomError(
                    'mac_address_format',
                    'Length and/or format of MAC address string is incorrect.',
                )

            # If pattern matches, the string format is correct
            delim, *_ = mac_match.groups()
            value = value.replace(delim, '')
            num_octets = len(value) // 2
            value = int(value, 16).to_bytes(num_octets, 'big')

        # Convert to bytes, zero-pad to nearest viable octet length
        if isinstance(value, int) and value >= 0:
            min_octets, rem = divmod(value.bit_length(), 8)
            min_octets += rem > 0

            for num_octets in (*VIABLE_OCTET_COUNTS, min_octets):
                if num_octets >= min_octets:
                    break

            value = value.to_bytes(num_octets, 'big')

        # At this point we should have a Sequence[int] format
        if not isinstance(value, Sequence) or not isinstance(value[0], int):
            raise PydanticCustomError(
                'mac_address_format',
                'MAC Address format unrecognized.',
            )

        # Sanity check our octets are actually octets
        if any([octet > 0xff for octet in value]):
            raise PydanticCustomError(
                'mac_address_format',
                'Octets are strictly 8-bit, cannot be bigger than 255.'
            )

        # Must have a Sequence of ints, finally length Check
        if len(value) not in VIABLE_OCTET_COUNTS:
            raise PydanticCustomError(
                'mac_address_format',
                'Length of MAC Address (number of octets) must be in {valid} got {n}.',
                {'valid': VIABLE_OCTET_COUNTS, 'n': len(value)}
            )

        return bytes(value)
