import common
m = common.real_module()
tests = {
 "plain64": "a"*64,
 "upper": "A"*64,
 "leading_space": " " + "a"*63,
 "trailing_space": "a"*63 + " ",
 "underscore": "a"*31 + "_" + "a"*32,   # 64 chars with underscore
 "plus_sign": "+" + "a"*63,
 "0x_prefix": "0x" + "a"*62,
 "newline": "\n" + "a"*63,
 "real_digest": m.sha256_hex({"x":1}),
}
for name,v in tests.items():
    print("%-16s len=%d is_sha256=%s" % (name, len(v), m.is_sha256(v)))
