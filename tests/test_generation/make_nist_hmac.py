# MIT License

# Copyright (c) 2018 brycx

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
This script converts the NIST HMAC.rsp test vector file into a format
that will be used to test orion. Only tests HMAC-SHA512
"""

lines = []

with open('src/tests/test_data/original/HMAC.rsp') as infile:
    outfile = open('src/tests/test_data/HMAC_fmt.rsp', 'w')
    # Set true if we have hit the value
    variant_sha512 = False
    test_case_number = 0
    # 375 is important. This is the total number of tests cases.
    outfile.write("let test_vectors: [[&str; 4]; 375] = [ ")

    for line in infile:
        if line.startswith("[L=64]"):
            variant_sha512 = True

        if variant_sha512 == True:
            lines.append(line)
            if line.startswith("Mac ="):
                test_case_number += 1

                key = (lines[-3].split(" = "))[1].rstrip()
                data = (lines[-2].split(" = "))[1].rstrip()
                tag = (lines[-1].split(" = "))[1].rstrip()
                tag_len = (lines[-4].split(" = "))[1].rstrip()
                # Below is a single test case
                single_test_case = ("\n[\"%s\", \"%s\", \"%s\", \"%s\"],\n" % (key, data, tag, tag_len))
                outfile.write(single_test_case)

outfile.write("\n];") #Finish off the array
outfile.close()

# Empty list
lines[:] = []
