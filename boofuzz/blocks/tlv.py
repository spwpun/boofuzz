from .. import exception, helpers
from builtins import range
import time
import random
import string
import struct

from ..fuzzable import Fuzzable


_fuzz_library_type = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,25,50,100,255,127] # + [i for i in range(20, 240)]

_fuzz_library_length = [0, 1, 255, 128, 127] #+ [i for i in range(2, 200)]

_fuzz_library_value = [
    b"",
    b"\x00",
    b"\xFF",
    b"\r\x15\xea^",
    b"\x00\x00",
    b"\x01\x00",
    b"\x00\x01",
    b"\x7F\xFF",
    b"\xFF\x7F",
    b"\xFE\xFF",
    b"\xFF\xFE",
    b"\xFF\xFF",
    b"\x00\x00\x00\x00",
    b"\x00\x00\x00\x01",
    b"\x01\x00\x00\x00",
    b"\x7F\xFF\xFF\xFF",
    b"\xFF\xFF\xFF\x7F",
    b"\xFE\xFF\xFF\xFF",
    b"\xFF\xFF\xFF\xFE",
    b"\xFF\xFF\xFF\xFF",
]

for _ in range(100):
    for i in range(random.randint(1, 310)):
        tmp = ''.join(random.sample(string.ascii_letters*5 + string.digits*5, i))
        _fuzz_library_value.append(helpers.str_to_bytes(tmp))
# for i in range(random.randint(1, 31)):
#     tmp = ''.join(random.sample(string.ascii_letters*5 + string.digits*5, i))
#     _fuzz_library_value.append(helpers.str_to_bytes(tmp))

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


class TLV(Fuzzable):
    """
    This mul_fields type is kind of special in that it is a type-length-value sequence.
    """


    def __init__(self, typev, length, value, fuzzable=True, name=None):
        """
        Defien a type that is a sequence of type-length-value.

        @type  type:       int or byte
        @param type:       Value of type
        @type  length:     int
        @param length:     Value of length
        @type  value:      int, byte or string
        @param value:      Value of value
        @type  fuzzable:   bool
        @param fuzzable:   (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  name:       str
        @param name:       (Optional, def=None) Specifying a name gives you direct access to a primitive
        """
        super(TLV, self).__init__()

        self._value_type = typev
        self._value_length = length
        self._value_value = value
        self._fuzzable = fuzzable
        self._name = name
        self._value = self._value_type

        self._original_value_type = typev  # default to nothing!
        self._original_value_length = length  # default to nothing!
        self._original_value_value = value  # default to nothing!
        self._rendered = b""  # rendered value
        self._fuzz_complete = False  # flag if this primitive has been completely fuzzed
        self._fuzz_library_type = _fuzz_library_type  # library of static fuzz heuristics to cycle through.
        self._fuzz_library_length = _fuzz_library_length  # library of static fuzz heuristics to cycle through.
        self._fuzz_library_value = _fuzz_library_value  # library of static fuzz heuristics to cycle through.
        self._mutant_index = 0  # current mutation number

        self._default_value = self.render()

        # init _fuzz_values by _fuzz_library
        for t in _fuzz_library_type:
            for l in _fuzz_library_length:
                for v in _fuzz_library_value:
                    tlv_field = t.to_bytes(1, byteorder='big') + l.to_bytes(1, byteorder='big') + v
                    self._fuzz_values.append(tlv_field)
        

    @property
    def name(self):
        return self._name

    @property
    def mutant_index(self):
        return self._mutant_index

    @property
    def fuzzable(self):
        return self._fuzzable

    def mutate(self):
        """
        Mutate the primitive by stepping through the fuzz library, return False on completion. If variable-bounding is
        specified then fuzzing is implicitly disabled. Instead, the render() routine will properly calculate the
        correct repetition and return the appropriate data.

        @rtype:  bool
        @return: True on success, False otherwise.
        """
        
        # if we've run out of mutations, raise the completion flag.
        if self.mutant_index == self.num_mutations():
            self._fuzz_complete = True

        # if fuzzing was disabled or complete, and mutate() is called, ensure the original value is restored.
        if not self.fuzzable or self._fuzz_complete:
            self._value_type = self._original_value_type
            self._value_length = self._original_value_length
            self._value_value = self._original_value_value
            return False

        # set the current value as a multiple
        if self.mutant_index < len(self._fuzz_library_type):
            self._value_type = self._fuzz_library_type[self.mutant_index]
            self._value = self._value_type
        elif self.mutant_index < len(self._fuzz_library_type) + len(self._fuzz_library_length):
            self._value_length = self._fuzz_library_length[self.mutant_index- len(self._fuzz_library_type)]
            self._value = self._value_length
        elif self.mutant_index < len(self._fuzz_library_type) + len(self._fuzz_library_length) + len(self._fuzz_library_value):
            self._value_value = self._fuzz_library_value[self.mutant_index - len(self._fuzz_library_type) - len(self._fuzz_library_length)]
            self._value = self._value_value
        else:
            self._value_type = random.randint(0, 256)
            self._value_length = random.randint(0, 256)
            tmp_value = ''.join(random.sample(string.ascii_letters*5 + string.digits*5, self._value_length))
            self._value_value = helpers.str_to_bytes(tmp_value)
            self._value = self._value_type

        # increment the mutation count.
        self._mutant_index += 1

        return True

    def num_mutations(self, default_value):
        """
        Determine the number of repetitions we will be making.

        @rtype:  int
        @return: Number of mutated forms this primitive can take.
        """

        return len(self._fuzz_library_type) + len(self._fuzz_library_length) + len(self._fuzz_library_value) + 5000

    @staticmethod
    def render_int(value, output_format, bit_width, endian, signed):
        """
        Convert value to a bit or byte string.

        Args:
            value (int): Value to convert to a byte string.
            output_format (str): "binary" or "ascii"
            bit_width (int): Width of output in bits.
            endian: BIG_ENDIAN or LITTLE_ENDIAN
            signed (bool):

        Returns:
            str: value converted to a byte string
        """
        if output_format == "binary":
            bit_stream = ""
            rendered = b""

            # pad the bit stream to the next byte boundary.
            if bit_width % 8 == 0:
                bit_stream += int_to_binary_string(value, bit_width)
            else:
                bit_stream = "0" * (8 - (bit_width % 8))
                bit_stream += int_to_binary_string(value, bit_width)

            # convert the bit stream from a string of bits into raw bytes.
            for i in range(len(bit_stream) // 8):
                chunk_min = 8 * i
                chunk_max = chunk_min + 8
                chunk = bit_stream[chunk_min:chunk_max]
                rendered += struct.pack("B", binary_string_to_int(chunk))

            # if necessary, convert the endianness of the raw bytes.
            if endian == ">":
                # reverse the bytes
                rendered = rendered[::-1]

            _rendered = rendered
        else:
            # Otherwise we have ascii/something else
            # if the sign flag is raised and we are dealing with a signed integer (first bit is 1).
            if signed and int_to_binary_string(value, bit_width)[0] == "1":
                max_num = binary_string_to_int("1" + "0" * (bit_width - 1))
                # chop off the sign bit.
                val = value & binary_string_to_int("1" * (bit_width - 1))

                # account for the fact that the negative scale works backwards.
                val = max_num - val - 1

                # toss in the negative sign.
                _rendered = "%d" % ~val

            # unsigned integer or positive signed integer.
            else:
                _rendered = "%d" % value
        return _rendered

    def render(self, value=None, mutation_context=None):
        """
        Nothing fancy on render, simply return the value.
        """

        temp_type = self.render_int(
            self._value_type, output_format="binary", bit_width=8, endian=">", signed=False
        )
        temp_length = self.render_int(
            self._value_length, output_format="binary", bit_width=8, endian=">", signed=False
        )
        if isinstance(self._value_value, int):
            temp_value = self.render_int(
                self._value_value, output_format="binary", bit_width=self._original_value_length *8, endian=">", signed=False
                )
            return helpers.str_to_bytes(temp_type) + helpers.str_to_bytes(temp_length) + helpers.str_to_bytes(temp_value)

        self._rendered_value = self._value_value
        return helpers.str_to_bytes(temp_type) + helpers.str_to_bytes(temp_length) + helpers.str_to_bytes(self._rendered_value)

    def reset(self):
        """
        Reset the fuzz state of this primitive.
        """
        self._fuzz_complete = False
        self._mutant_index = 0
        self._value_type = self._original_value_type
        self._value_length = self._original_value_length
        self._value_value = self._original_value_value

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self._name)

    def __bool__(self):
        """
        Make sure instances evaluate to True even if __len__ is zero.

        :return: True
        """
        return True
