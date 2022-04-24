import struct

import six
from builtins import range
from past.builtins import map

from .base_primitive import BasePrimitive
from .. import helpers
from ..constants import LITTLE_ENDIAN


def binary_string_to_int(binary):
    """
    Convert a binary string to a decimal number.

    @type  binary: str
    @param binary: Binary string

    @rtype:  int
    @return: Converted bit string
    """

    return int(binary, 2)


def int_to_binary_string(number, bit_width):
    """
    Convert a number to a binary string.

    @type  number:    int
    @param number:    (Optional, def=self._value) Number to convert
    @type  bit_width: int
    @param bit_width: (Optional, def=self.width) Width of bit string

    @rtype:  str
    @return: Bit string
    """
    return "".join(map(lambda x: str((number >> x) & 1), range(bit_width - 1, -1, -1)))


class SingleBit(BasePrimitive):
    def __init__(
        self,
        value,
        request,
        width,
        max_num=None,
        endian=LITTLE_ENDIAN,
        full_range=False,
        fuzzable=True,
        name=None,
        follow=True,
        field_type=None,
    ):
        """
        The bit field primitive represents a number of variable length and is used to define all other integer types.

        @type  value:         int
        @param value:         Default integer value
        @type  width:         int
        @param width:         Width of bit fields
        @type  max_num:       int
        @param max_num:       Maximum number to iterate up to
        @type  endian:        chr
        @param endian:        (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
        @type  full_range:    bool
        @param full_range:    (Optional, def=False) If enabled the field mutates through *all* possible values.
        @type  fuzzable:      bool
        @param fuzzable:      (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  name:          str
        @param name:          (Optional, def=None) Specifying a name gives you direct access to a primitive
        """

        super(SingleBit, self).__init__()

        assert isinstance(value, (six.integer_types, list, tuple)), "value must be an integer, list, or tuple!"
        assert isinstance(width, six.integer_types), "width must be an integer!"

        self._value = self._original_value = value
        self.request = request
        self.width = width
        self.max_num = max_num
        self.endian = endian
        self.full_range = full_range
        self._fuzzable = fuzzable
        self._name = name
        self.follow = follow
        self.field_type= field_type
        self.cyclic_index = 0  # when cycling through non-mutating values

        if not self.max_num:
            self.max_num = binary_string_to_int("1" + "0" * width)

        assert isinstance(self.max_num, six.integer_types), "max_num must be an integer!"

        if isinstance(value, (list, tuple)):
            # Use the supplied values as the fuzz library.
            for val in iter(value):
                if val < self.max_num:
                    self._fuzz_library.append(val)

            # Use the first value of the supplied values as the default value if it exists, 0 else.
            val = 0 if len(value) == 0 else value[0]
            self._value = self._original_value = val

            # TODO: Add injectable arbitrary bit fields
        else:
            for i in range(0, self.max_num):
                self._fuzz_library.append(i)
            

    @property
    def name(self):
        return self._name


    def mutate(self):
        fuzz_complete = False
        # if we've ran out of mutations, raise the completion flag.
        if self._mutant_index == self.num_mutations():
            self._fuzz_complete = True
            fuzz_complete = True

        # if fuzzing was disabled or complete, and mutate() is called, ensure the original value is restored.
        if not self._fuzzable or fuzz_complete:
            self._value = self._original_value
            return False
            
        self._value = self._fuzz_library[self._mutant_index]

        # increment the mutation count.
        self._mutant_index += 1

        return True


    def num_mutations(self):
        """
        Calculate and return the total number of mutations for this individual primitive.

        @rtype:  int
        @return: Number of mutated forms this primitive can take
        """
        #return len(self._fuzz_library) + len(self._fuzz_int)
        return len(self._fuzz_library)

    def _render(self, value):

        temp = ''
        temp_length = 0

        if self.follow:
            return b''
        else:
            for item in self.request.walk():
                if isinstance(item, SingleBit):
                    if item.follow == True:
                        temp += int_to_binary_string(item._value, item.width)
                    else:
                        temp += int_to_binary_string(self._value, self.width)
                        break
                    temp_length += item.width
            temp_length += self.width
            return_temp = binary_string_to_int(temp)
            return return_temp.to_bytes(length=int(temp_length/8),byteorder='big',signed=False)
            #return six.int2bytes(return_temp)


    def __len__(self):
        return len(self._render(self._value))
        # if self.follow:
        #     return 0
        # else:
        #     for item in self.request.walk():
        #         if isinstance(item, SingleBit):
        #             temp_length += item.width
        #     return int(temp_length/8)


    def __bool__(self):
        """
        Make sure instances evaluate to True even if __len__ is zero.

        :return: True
        """
        return True
