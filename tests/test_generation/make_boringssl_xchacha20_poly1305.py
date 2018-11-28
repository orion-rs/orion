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

with open('src/tests/test_data/original/boringssl_xchacha20_poly1305.txt') as infile:
    outfile = open('src/tests/test_data/boringssl_xchacha20_poly1305_fmt.txt', 'w')
    test_case_number = 0

    for line in infile:
        lines.append(line)

        if line.startswith("TAG: "):
            test_case_number += 1
            key = (lines[-6].split(": "))[1].rstrip()
            nonce = (lines[-5].split(": "))[1].rstrip()

            try:
                ad = (lines[-3].split(": "))[1].rstrip()
            except:
                ad = ""

            try:
                input = (lines[-4].split(": "))[1].rstrip()
                ct = (lines[-2].split(": "))[1].rstrip()
            except:
                test_case_number -= 1
                # Something went wrong processing the test vectors
                # Most likely an empty test vectors without a space after :
                # This test vector is skipped as orion does not allow empty input
                continue

            tag = (lines[-1].split(": "))[1].rstrip()

            rust_func_start = "\n#[test]\n"
            rust_func_start += ("fn boringssl_test_case_%d() {" % test_case_number)

            rust_func_body_and_end = (
"""
    let key = decode(\"%s\").unwrap();
    let nonce = decode(\"%s\").unwrap();
    let aad = decode(\"%s\").unwrap();
    let input = decode(\"%s\").unwrap();
    let output = decode(\"%s\").unwrap();
    let tag = decode(\"%s\").unwrap();

    xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
}
""" % (key, nonce, ad, input, ct, tag))

            outfile.write(rust_func_start + rust_func_body_and_end)

outfile.close()
