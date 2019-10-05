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

    aead_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
}
""" % (key, nonce, ad, input, ct, tag))

            outfile.write(rust_func_start + rust_func_body_and_end)

outfile.close()
