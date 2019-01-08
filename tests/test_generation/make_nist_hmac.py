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
