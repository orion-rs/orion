# NOTE: As this currently splits at ": " the first test vector is malformed on
# conversion, so this has to be manually updated.

# Furthermore, those test vectors where the parameter is a string and not hex
# this must be updated in the converted file too. The one test vector with empty
# input should be commented out.

lines = []

with open('src/tests/test_data/original/boringssl_chacha20_poly1305.txt') as infile:
    outfile = open('src/tests/test_data/boringssl_chacha20_poly1305_fmt.txt', 'w')
    test_case_number = 0

    for line in infile:
        lines.append(line)

        if line.startswith("TAG: "):
            test_case_number += 1
            key = (lines[-6].split(": "))[1].rstrip()
            nonce = (lines[-5].split(": "))[1].rstrip()
            input = (lines[-4].split(": "))[1].rstrip()
            ad = (lines[-3].split(": "))[1].rstrip()
            ct = (lines[-2].split(": "))[1].rstrip()
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

    aead_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
}
""" % (key, nonce, ad, input, ct, tag))

            outfile.write(rust_func_start + rust_func_body_and_end)

outfile.close()
