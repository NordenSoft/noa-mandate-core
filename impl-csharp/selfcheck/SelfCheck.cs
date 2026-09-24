using System.Numerics;
using System.Text.Json;
using NoaReceipt;

// Key-load self-check: strict public-key validation refuses non-canonical, small-order and
// mixed-order Ed25519 key encodings at key load (Crypto.SpkiToRaw), and strict signature-R
// validation refuses non-canonical and small-order R. Usage: noa-verify-selfcheck <conformance/vectors>
if (args.Length != 1)
{
    Console.Error.WriteLine("usage: noa-verify-selfcheck <conformance/vectors directory>");
    return 4;
}
string vectors = args[0];
string strictDir = Path.Combine(vectors, "strict-ed25519");
int pass = 0, fail = 0;

string SingleKey(string file)
{
    using var doc = JsonDocument.Parse(File.ReadAllText(file));
    return doc.RootElement.EnumerateObject().Single().Value.GetString()!;
}

void Expect(bool ok, string label)
{
    if (ok) pass++; else fail++;
    Console.WriteLine($"  {(ok ? "ok  " : "FAIL")}  {label}");
}

string[] keyrings = Directory.GetFiles(strictDir, "keyring-*.json").OrderBy(f => f, StringComparer.Ordinal).ToArray();
if (keyrings.Length == 0)
{
    Console.WriteLine($"  FAIL  no keyring-*.json under {strictDir}");
    return 1;
}
foreach (string file in keyrings)
{
    bool refused;
    try { Crypto.SpkiToRaw(SingleKey(file)); refused = false; }
    catch (FormatException) { refused = true; }
    Expect(refused, $"key load refuses {Path.GetFileName(file)}");
    byte[] raw = Convert.FromBase64String(SingleKey(file)).Skip(12).ToArray();
    Expect(!Crypto.IsStrictPublicKey(raw), $"IsStrictPublicKey refuses {Path.GetFileName(file)}");
    if (!Path.GetFileName(file).Contains("mixed-order", StringComparison.Ordinal))
        Expect(!Crypto.IsStrictSignatureR(raw), $"IsStrictSignatureR refuses {Path.GetFileName(file)}");
}

// Knockout proof (signature-R rule): a fresh key and key-holder signatures made at run time
// (S = r + k*a with its own private scalar; nothing committed as bytes).
{
    byte[] seed = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
    byte[] pub = new byte[32];
    Org.BouncyCastle.Math.EC.Rfc8032.Ed25519.GeneratePublicKey(seed, 0, pub, 0);
    byte[] h = System.Security.Cryptography.SHA512.HashData(seed);
    h[0] &= 248; h[31] = (byte)((h[31] & 127) | 64);
    BigInteger a = Le(h, 32);
    BigInteger[] basePoint = Extended("5866666666666666666666666666666666666666666666666666666666666666");
    Expect(Encode(ScalarMul(a, basePoint)).SequenceEqual(pub), "test key derivation matches BouncyCastle");
    BigInteger r = Crypto.Mod(Le(System.Security.Cryptography.SHA512.HashData(seed.Append((byte)'r').ToArray()), 64)) % Crypto.L;
    byte[] msg = System.Text.Encoding.UTF8.GetBytes("signature-R rule");
    byte[] identity = Convert.FromHexString("0100000000000000000000000000000000000000000000000000000000000000");
    byte[] identitySigned = Convert.FromHexString("0100000000000000000000000000000000000000000000000000000000000080");
    byte[] mixedR = Encode(Crypto.ExtendedAdd(ScalarMul(r, basePoint), Extended("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")));
    Expect(Crypto.Ed25519Verify(pub, msg, SignWithR(a, pub, msg, Encode(ScalarMul(r, basePoint)), r)), "the control signature verifies");
    Expect(!Crypto.Ed25519Verify(pub, msg, SignWithR(a, pub, msg, identity, BigInteger.Zero)), "R = identity is refused");
    Expect(!Crypto.Ed25519Verify(pub, msg, SignWithR(a, pub, msg, identitySigned, BigInteger.Zero)), "R = identity spelled with the sign bit is refused");
    Expect(!Crypto.Ed25519Verify(pub, msg, SignWithR(a, pub, msg, mixedR, r)), "R = rB + small-order point is refused");
}

string corpusKey = SingleKey(Path.Combine(vectors, "keyring.json"));
bool accepted;
try { Crypto.SpkiToRaw(corpusKey); accepted = true; }
catch (FormatException) { accepted = false; }
Expect(accepted, "key load accepts the corpus key (keyring.json)");

Console.WriteLine($"key-load self-check: {pass}/{pass + fail} passed");
return fail == 0 ? 0 : 1;

static BigInteger Le(byte[] b, int len)
{
    BigInteger v = BigInteger.Zero;
    for (int i = len - 1; i >= 0; i--) v = (v << 8) | b[i];
    return v;
}

static byte[] ToLe32(BigInteger v)
{
    var o = new byte[32];
    for (int i = 0; i < 32; i++) { o[i] = (byte)(v & 0xff); v >>= 8; }
    return o;
}

static BigInteger[] Extended(string hex)
{
    BigInteger[] p = Crypto.StrictDecode(Convert.FromHexString(hex)) ?? throw new InvalidOperationException(hex);
    return new[] { p[0], p[1], BigInteger.One, Crypto.Mod(p[0] * p[1]) };
}

static BigInteger[] ScalarMul(BigInteger s, BigInteger[] p)
{
    var acc = new[] { BigInteger.Zero, BigInteger.One, BigInteger.One, BigInteger.Zero };
    for (int i = (int)s.GetBitLength() - 1; i >= 0; i--)
    {
        acc = Crypto.ExtendedAdd(acc, acc);
        if (!((s >> i) & BigInteger.One).IsZero) acc = Crypto.ExtendedAdd(acc, p);
    }
    return acc;
}

static byte[] Encode(BigInteger[] p)
{
    BigInteger zi = BigInteger.ModPow(p[2], Crypto.Q - 2, Crypto.Q);
    BigInteger x = Crypto.Mod(p[0] * zi), y = Crypto.Mod(p[1] * zi);
    byte[] o = ToLe32(y);
    if (!x.IsEven) o[31] |= 0x80;
    return o;
}

static byte[] SignWithR(BigInteger a, byte[] pub, byte[] msg, byte[] rBytes, BigInteger r)
{
    byte[] k = System.Security.Cryptography.SHA512.HashData(rBytes.Concat(pub).Concat(msg).ToArray());
    BigInteger s = (r + (Le(k, 64) % Crypto.L) * a) % Crypto.L;
    return rBytes.Concat(ToLe32(s)).ToArray();
}
