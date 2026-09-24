using System.Numerics;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace NoaReceipt;

/// <summary>
/// Ed25519 verification + SPKI/base64 handling, byte-for-byte strict with impl-py/noa_verify.py
/// and src/keys.ts. BouncyCastle performs the core RFC 8032 group equation; every strictness rule
/// that makes independent verifiers AGREE is re-implemented here at the boundary rather than left
/// to a library's runtime behavior:
///   - canonical base64 (round-trip) for both the signature and the keyring SPKI;
///   - exact 12-byte Ed25519 SPKI prefix + 44-byte length;
///   - strict public-key validation at key load (IsStrictPublicKey): refuse non-canonical and
///     small-order key encodings (RFC 8032 §5.1.3 decoding + small-order rejection);
///   - S &lt; L scalar check (Ed25519 signature malleability, RFC 8032 §5.1.7).
/// </summary>
public static class Crypto
{
    // AlgorithmIdentifier{1.3.101.112} + BIT STRING header for an Ed25519 SPKI.
    private static readonly byte[] SpkiPrefix = FromHex("302a300506032b6570032100");

    internal static readonly BigInteger Q = (BigInteger.One << 255) - 19;
    internal static readonly BigInteger L =
        (BigInteger.One << 252) + BigInteger.Parse("27742317777372353535851937790883648493");

    // The 8 canonical small-order Ed25519 public-key encodings (torsion subgroup, order dividing 8).
    // Mirrors SMALL_ORDER_PUBKEYS in src/keys.ts + impl-py. Which encodings a library admits as a
    // public key differs between libraries, so every verifier refuses these itself; a legitimate
    // signing key is never a low-order point.
    private static readonly HashSet<string> SmallOrder = new(StringComparer.Ordinal)
    {
        "0100000000000000000000000000000000000000000000000000000000000000", // order 1 (identity)
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 2
        "0000000000000000000000000000000000000000000000000000000000000000", // order 4
        "0000000000000000000000000000000000000000000000000000000000000080", // order 4
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8
    };

    /// <summary>
    /// Strict CANONICAL base64: .NET's decoder tolerates embedded whitespace and does not reject
    /// non-canonical trailing bits, so we require the decoded bytes to RE-ENCODE to exactly the
    /// input (parity with Python base64.b64decode(validate=True) + canonical round-trip and the TS
    /// Buffer.from round-trip). Throws on any non-canonical / non-alphabet input.
    /// </summary>
    public static byte[] StrictB64Decode(string s)
    {
        byte[] raw;
        try
        {
            raw = System.Convert.FromBase64String(s);
        }
        catch (Exception)
        {
            throw new FormatException("invalid base64");
        }
        if (System.Convert.ToBase64String(raw) != s)
            throw new FormatException("non-canonical base64");
        return raw;
    }

    /// <summary>base64(DER SPKI Ed25519) → raw 32-byte key. Rejects non-canonical base64, a wrong
    /// SPKI prefix/length, and any key that fails strict public-key validation (parity with
    /// spki_to_raw).</summary>
    public static byte[] SpkiToRaw(string pubB64)
    {
        byte[] der = StrictB64Decode(pubB64);
        if (der.Length != 44 || !PrefixMatches(der))
            throw new FormatException("not a canonical Ed25519 SPKI");
        var raw = new byte[32];
        Array.Copy(der, 12, raw, 0, 32);
        if (!IsStrictPublicKey(raw))
            throw new FormatException("strict public-key validation: non-canonical or small-order Ed25519 key refused");
        return raw;
    }

    // Edwards curve constant d = -121665/121666 mod q, and sqrt(-1) mod q (RFC 8032 §5.1, §5.1.3).
    private static readonly BigInteger D = BigInteger.Parse(
        "37095705934669439343138083508754565189542113879843219016388785533085940283555");
    private static readonly BigInteger SqrtM1 = BigInteger.Parse(
        "19681161376707505956807079304988542015446066515923890162744021073123829784752");

    /// <summary>
    /// Strict RFC 8032 §5.1.3 decoding of a 32-byte point encoding into affine (x, y), or null when:
    ///   1. the y coordinate (the low 255 bits) is not canonical (y &gt;= q);
    ///   2. y does not decode to a curve point: x^2 = (y^2 - 1) / (d*y^2 + 1) has no square root;
    ///   3. x = 0 and the sign bit is set (RFC 8032 §5.1.3 step 4).
    /// Same steps, same order, as src/keys.ts decodeStrictEd25519Point and impl-py _strict_decode.
    /// </summary>
    internal static BigInteger[]? StrictDecode(byte[] raw)
    {
        if (raw.Length != 32) return null;
        bool xSign = (raw[31] & 0x80) != 0;
        if (!PublicKeyYCanonical(raw)) return null;
        var yBytes = new byte[32];
        Array.Copy(raw, yBytes, 32);
        yBytes[31] = (byte)(yBytes[31] & 0x7f);
        BigInteger y = LittleEndianToBig(yBytes, 0, 32);
        BigInteger y2 = (y * y) % Q;
        BigInteger u = ((y2 - 1) % Q + Q) % Q;
        BigInteger v = (D * y2 + 1) % Q;
        BigInteger v3 = BigInteger.ModPow(v, 3, Q);
        BigInteger v7 = BigInteger.ModPow(v, 7, Q);
        BigInteger x = (u * v3 % Q) * BigInteger.ModPow(u * v7 % Q, (Q - 5) / 8, Q) % Q;
        BigInteger vx2 = v * (x * x % Q) % Q;
        if (vx2 != u)
        {
            if (vx2 != (Q - u) % Q) return null;
            x = x * SqrtM1 % Q;
        }
        if (x.IsZero && xSign) return null;
        if (!x.IsEven != xSign) x = Q - x;
        return new[] { x, y };
    }

    internal static BigInteger Mod(BigInteger a) { BigInteger r = a % Q; return r.Sign < 0 ? r + Q : r; }

    /// <summary>RFC 8032 §5.1.4 addition on extended coordinates [X, Y, Z, T]; complete, so it also doubles.</summary>
    internal static BigInteger[] ExtendedAdd(BigInteger[] p, BigInteger[] q)
    {
        BigInteger a = Mod((p[1] - p[0]) * (q[1] - q[0]));
        BigInteger b = Mod((p[1] + p[0]) * (q[1] + q[0]));
        BigInteger c = Mod(Mod(2 * p[3]) * Mod(q[3] * D));
        BigInteger d = Mod(Mod(2 * p[2]) * q[2]);
        BigInteger e = b - a, f = d - c, g = d + c, h = b + a;
        return new[] { Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h) };
    }

    /// <summary>True when [L]P is the identity, i.e. P lies in the prime-order subgroup.</summary>
    private static bool InPrimeOrderSubgroup(BigInteger[] point)
    {
        var baseP = new[] { point[0], point[1], BigInteger.One, Mod(point[0] * point[1]) };
        var acc = new[] { BigInteger.Zero, BigInteger.One, BigInteger.One, BigInteger.Zero };
        for (int i = (int)L.GetBitLength() - 1; i >= 0; i--)
        {
            acc = ExtendedAdd(acc, acc);
            if (!((L >> i) & BigInteger.One).IsZero) acc = ExtendedAdd(acc, baseP);
        }
        return Mod(acc[0]).IsZero && Mod(acc[1] - acc[2]).IsZero;
    }

    /// <summary>
    /// STRICT PUBLIC-KEY VALIDATION: refuse non-canonical and small-order Ed25519 key encodings
    /// (RFC 8032 §5.1.3 decoding + small-order rejection) and keys outside the prime-order subgroup.
    /// Same rule, same order, as impl-py _is_strict_public_key and src/keys.ts
    /// isStrictEd25519PublicKeyBytes:
    ///   1-3. strict decoding (StrictDecode);
    ///   4. not one of the 8 small-order points (canonical encodings; steps 1-3 leave no other spelling);
    ///   5. in the prime-order subgroup: [L]A = identity (refuses mixed-order keys).
    /// A key produced by Ed25519 key generation passes every step.
    /// </summary>
    public static bool IsStrictPublicKey(byte[] raw)
    {
        BigInteger[]? point = StrictDecode(raw);
        if (point == null || SmallOrder.Contains(ToHex(raw))) return false;
        return InPrimeOrderSubgroup(point);
    }

    /// <summary>
    /// STRICT SIGNATURE-R VALIDATION: R is canonically encoded (steps 1-3) and not small-order (step 4).
    /// </summary>
    public static bool IsStrictSignatureR(byte[] raw)
    {
        return StrictDecode(raw) != null && !SmallOrder.Contains(ToHex(raw));
    }

    /// <summary>True iff <paramref name="signature"/> (64 bytes) is a valid Ed25519 signature over
    /// <paramref name="message"/> for the raw 32-byte <paramref name="public32"/>. Never throws.</summary>
    public static bool Ed25519Verify(byte[] public32, byte[] message, byte[] signature)
    {
        try
        {
            if (signature.Length != 64 || public32.Length != 32) return false;

            // S < L (RFC 8032 §5.1.7): reject a non-canonical / malleated scalar (S' = S + L).
            BigInteger s = LittleEndianToBig(signature, 32, 32);
            if (s >= L) return false;

            // The key rule (SpkiToRaw applies it at key load; repeated here so this entry point is
            // strict on its own).
            if (!IsStrictPublicKey(public32)) return false;

            // R must be canonically encoded and not small-order (the same rule in all five
            // verifiers), and must lie in the prime-order subgroup. With a prime-order key this makes
            // the verdict equal to the cofactorless equation [S]B = R + [k]A whatever equation the
            // library evaluates: a prime-order R and A leave no small-order term for a cofactor to clear.
            var r = new byte[32];
            Array.Copy(signature, r, 32);
            BigInteger[]? rPoint = StrictDecode(r);
            if (rPoint == null || SmallOrder.Contains(ToHex(r)) || !InPrimeOrderSubgroup(rPoint)) return false;

            return Ed25519.Verify(signature, 0, public32, 0, message, 0, message.Length);
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static bool PublicKeyYCanonical(byte[] pub32)
    {
        var y = new byte[32];
        Array.Copy(pub32, y, 32);
        y[31] = (byte)(y[31] & 0x7f); // clear the x-sign bit (bit 255)
        BigInteger yv = LittleEndianToBig(y, 0, 32);
        return yv < Q;
    }

    private static BigInteger LittleEndianToBig(byte[] data, int off, int len)
    {
        BigInteger v = BigInteger.Zero;
        for (int i = off + len - 1; i >= off; i--)
            v = (v << 8) | data[i];
        return v;
    }

    private static bool PrefixMatches(byte[] der)
    {
        for (int i = 0; i < SpkiPrefix.Length; i++)
            if (der[i] != SpkiPrefix[i]) return false;
        return true;
    }

    private static byte[] FromHex(string hex)
    {
        var b = new byte[hex.Length / 2];
        for (int i = 0; i < b.Length; i++)
            b[i] = System.Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return b;
    }

    private static string ToHex(byte[] data)
    {
        var sb = new System.Text.StringBuilder(data.Length * 2);
        foreach (byte b in data) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }
}
