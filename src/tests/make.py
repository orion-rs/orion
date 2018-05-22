cavp_encryption = [
    'HMAC.rsp',
]

keyword_replacements = {
    'Msg' : 'Input',
    'Mac' : 'Output',
}

lines = []

for file in cavp_encryption:
    with open('src/tests/test_data/' + file) as infile:
        for line in infile:
            for src, target in keyword_replacements.items():
                line = line.replace(src, target)
            #if line.endswith("= \n"):
            #    line = line.replace(' = ', ' = ""')


            variant = 0
            # We to check the most recent [L=] tag and set HMAC to that instead
            if line.startswith("[L=32]"):
                variant = 256
            if line.startswith("[L=48]"):
                variant = 384
            if line.startswith("[L=64]"):
                variant = 512

            if not line.startswith("Output") or ((len(line) == 74) and variant == 256) or ((len(line) == 106) and variant == 384) or ((len(line) == 138) and variant == 512):
                if not line.startswith("["):
                    if not line.startswith("Count"):
                        if not line.startswith("Klen"):
                            if not line.startswith("Tlen"):
                                lines.append(line)
                            if line.startswith("Output"):
                                # Without newline chars, 73, 105, 137
                                if len(line) == 74:
                                    lines.insert(-3, "HMAC = SHA256\n")
                                if len(line) == 106:
                                    lines.insert(-3, "HMAC = SHA384\n")
                                if len(line) == 138:
                                    lines.insert(-3, "HMAC = SHA512\n")
            else:
                for x in range(1,3):
                    lines.pop()

    with open('src/tests/test_data/' + file + '_fmt.rsp', 'w') as outfile:
        for line in lines:
            outfile.write(line)

    # Empty list
    lines[:] = []