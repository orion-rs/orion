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

with open('src/tests/test_data/Wycheproof_ChaCha20_Poly1305.json') as json_file:
    # Store outfile
    outfile = open('src/tests/test_data/Wycheproof_ChaCha20_Poly1305_fmt.txt', 'w')

    json_data = json.load(json_file)

    for group in json_data["testGroups"]:
        for test_case in group["tests"]:
            test_case_number = test_case["tcId"]
            key = test_case["key"]
            nonce = test_case["iv"]
            aad = test_case["aad"]
            msg = test_case["msg"]
            ct = test_case["ct"]
            tag = test_case["tag"]
            result = test_case["result"]
            test_case_comment = test_case["comment"]

            rust_func_start = "\n#[test]\n"
            if result == "invalid":
                rust_func_start += "\n#[should_panic]\n"

            rust_func_start += ("fn wycheproof_test_case_%d() {" % test_case_number)

            rust_func_body_and_end = (
"""
    let key = decode(\"%s\").unwrap();
    let nonce = decode(\"%s\").unwrap();
    let aad = decode(\"%s\").unwrap();
    let input = decode(\"%s\").unwrap();
    let output = decode(\"%s\").unwrap();
    let tag = decode(\"%s\").unwrap();

    // Wycheproof test case comment: %s

    chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output);
}
""" % (key, nonce, aad, msg, ct, tag, test_case_comment))

            outfile.write(rust_func_start + rust_func_body_and_end)

    outfile.close()
