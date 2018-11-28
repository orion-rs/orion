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

lines = []

with open('src/tests/test_data/original/boringssl_poly1305.txt') as infile:
    outfile = open('src/tests/test_data/boringssl_poly1305_fmt.txt', 'w')

    test_case_number = 0

    for line in infile:
        lines.append(line)
        if line.startswith("MAC = "):
            test_case_number += 1

            key = (lines[-3].split(" = "))[1].rstrip()
            data = (lines[-2].split(" = "))[1].rstrip()
            tag = (lines[-1].split(" = "))[1].rstrip()

            rust_func_start = "\n#[test]\n"
            rust_func_start += ("fn boringssl_poly1305_test_case_%d() {" % test_case_number)

            rust_func_body_and_end = (
"""
    let key = decode(\"%s\").unwrap();
    let input = decode(\"%s\").unwrap();
    let tag = decode(\"%s\").unwrap();

    poly1305_test_runner(&key, &input, &tag).unwrap();
}
""" % (key, data, tag))

            outfile.write(rust_func_start + rust_func_body_and_end)

outfile.close()

# Empty list
lines[:] = []
