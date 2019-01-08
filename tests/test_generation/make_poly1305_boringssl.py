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
