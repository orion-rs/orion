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

import json

with open('src/tests/test_data/original/blake2-kat.json') as json_file:
    # Store outfile
    outfile = open('src/tests/test_data/blake2-kat_fmt.txt', 'w')
    outfile.write("let test_vectors: [[&str; 3]; 2048] = [ ")

    json_data = json.load(json_file)

    test_case_number = 0

    for variant in json_data:
        if variant["hash"] == "blake2b":
            for testvector in variant:
                input = variant["in"]
                key = variant["key"]
                output = variant["out"]

                single_test_case = ("\n[\"%s\", \"%s\", \"%s\"],\n" % (input, key, output))
                outfile.write(single_test_case)

outfile.write("\n];") #Finish off the array
outfile.close()

outfile.close()
