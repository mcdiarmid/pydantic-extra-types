"""
The MAC address module provides functionality to parse and validate MAC addresses in different
formats, such as IEEE 802 MAC-48, EUI-48, EUI-64, or a 20-octet format.
"""

from __future__ import annotations

from typing import Any, Sequence

from pydantic import GetCoreSchemaHandler
from pydantic_core import PydanticCustomError, core_schema

VIABLE_OCTET_COUNTS = 6, 8, 20

class MacAddress(str):
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
        return core_schema.with_info_before_validator_function(
            cls._validate,
            core_schema.str_schema(),
        )

    @classmethod
    def _validate(cls, __input_value: str | int | Sequence[int], _: Any) -> str:
        """
        Validate a MAC Address from the provided str value.

        Args:
            __input_value: The str value to be validated.
            _: The source type to be converted.

        Returns:
            str: The parsed MAC address.

        """
        return cls.validate_mac_address(__input_value)

    @staticmethod
    def validate_mac_address(value: str | int | Sequence[int]) -> str:
        """
        Validate a MAC Address from the provided byte value.
        """
        # Split by delimeter
        num_octets = 0
        if isinstance(value, str):
            delim = ''
            if value[2] in ':-':
                delim = value[2]
            elif value[4] == '.':
                delim = value[4]

            # Entire string should be hex after removing delimeter
            try:
                value.replace(delim, '')
                num_octets = len(value) // 2
                value = int(value, 16)
            except ValueError:
                raise PydanticCustomError(
                    'mac_address_format',
                    'MAC Address string must contain only hexadecimal characters '
                    'delimited by one of ":", "-", or ".". '
                    '{input=} does not follow this formatting convention.',
                    {'input': value}
                )

        # Convert to bytes, zero-pad to nearest viable octet length
        if isinstance(value, int):
            min_octets, rem = divmod(value.bit_length(), 8)
            min_octets += rem > 0

            if min_octets > max(VIABLE_OCTET_COUNTS):
                num_octets = min_octets

            if num_octets == 0:
                for num_octets in VIABLE_OCTET_COUNTS:
                    if num_octets >= min_octets:
                        break

            value = value.to_bytes(num_octets, 'big')

        # At this point we should have a Sequence[int] format
        if not isinstance(value, Sequence) or not isinstance(value[0], int):
            raise PydanticCustomError(
                'mac_address_type',
                'MAC Address ({input=}) not of type str, int, or Sequence[int].',
                {'input': value} 
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
                'Number of octets in MAC Address must be in {valid} got {n}.',
                {'valid': VIABLE_OCTET_COUNTS, 'n': len(value)}
            )

        return bytes(value).hex(':')
