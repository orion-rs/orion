"""
This script converts the NIST HMAC.rsp test vector file into a format
that will be used to test orion. Some input paramters are changed,
and only the test vectors for HMAC-SHA256, HMAC-SHA384 and HMAC-SHA512 are
kept. Any test vectors that have truncated output are also removed.

This means orion tests against the test vectors for an HMAC with the
exact matching output size.
"""

keyword_replacements = {
    'Msg' : 'Input',
    'Mac' : 'Output',
}

lines = []

with open('src/tests/test_data/HMAC.rsp') as infile:
    
    # Stores the most recent [Len=] parameter from original .rsp
    variant = 0

    for line in infile:
        for src, target in keyword_replacements.items():
            line = line.replace(src, target)

        # Check if output is accepted SHA variant and length
        Output_is_valid = False
        
        # Set HMAC with SHA variant tag according to [Len=] param
        if line.startswith("[L=32]"):
            variant = 256
        if line.startswith("[L=48]"):
            variant = 384
        if line.startswith("[L=64]"):
            variant = 512

        if line.startswith("Output") and len(line) == 74 and variant == 256:
            Output_is_valid = True
        if line.startswith("Output") and len(line) == 106 and variant == 384:
            Output_is_valid = True
        if line.startswith("Output") and len(line) == 138 and variant == 512:
            Output_is_valid = True

        # If two consecutive newlines appear, remove one
        if line == "\n" and lines[-1] == "\n":
            lines.pop()

        if not line.startswith("Output") or Output_is_valid is True:
        #if not line.startswith("Output") or (len(line) == 74) or (len(line) == 106) or (len(line) == 136):
            if not line.startswith("["):
                if not line.startswith("Count"):
                    if not line.startswith("Klen"):
                        if not line.startswith("Tlen"):
                            lines.append(line)
                        if line.startswith("Output"):
                            # Without newline chars, 73, 105, 137
                            if variant == 256:
                                lines.insert(-3, "HMAC = SHA256\n")
                            if variant == 384:
                                lines.insert(-3, "HMAC = SHA384\n")
                            if variant == 512:
                                lines.insert(-3, "HMAC = SHA512\n")
        else:
            # If the output is truncated, then we remove the last three inserted lines
            for x in range(1,3):
                lines.pop()

with open('src/tests/test_data/HMAC_fmt.rsp', 'w') as outfile:
    for line in lines:
        outfile.write(line)

# Empty list
lines[:] = []