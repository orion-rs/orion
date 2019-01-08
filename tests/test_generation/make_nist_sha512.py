lines = []

with open('src/tests/test_data/original/SHA512LongMsg.rsp') as infile:
    outfile = open('src/tests/test_data/SHA512LongMsg_fmt.txt', 'w')
    test_case_number = 0
    # 128 is important. This is the total number of tests cases.
    outfile.write("let test_vectors: [[&str; 2]; 128] = [ ")

    for line in infile:
    	lines.append(line)
        if line.startswith("MD ="):
            test_case_number += 1

            data = (lines[-2].split(" = "))[1].rstrip()
            digest = (lines[-1].split(" = "))[1].rstrip()
            # Below is a single test case
            single_test_case = ("\n[\"%s\", \"%s\"],\n" % (data, digest))
            outfile.write(single_test_case)

outfile.write("\n];") #Finish off the array
outfile.close()
print(test_case_number)

# Empty list
lines[:] = []

with open('src/tests/test_data/original/SHA512ShortMsg.rsp') as infile:
    outfile = open('src/tests/test_data/SHA512ShortMsg_fmt.txt', 'w')
    test_case_number = 0
    # 129 is important. This is the total number of tests cases.
    outfile.write("let test_vectors: [[&str; 2]; 129] = [ ")

    for line in infile:
    	lines.append(line)
        if line.startswith("MD ="):
            test_case_number += 1

            data = (lines[-2].split(" = "))[1].rstrip()
            digest = (lines[-1].split(" = "))[1].rstrip()
            # Below is a single test case
            single_test_case = ("\n[\"%s\", \"%s\"],\n" % (data, digest))
            outfile.write(single_test_case)

outfile.write("\n];") #Finish off the array
outfile.close()
print(test_case_number)




