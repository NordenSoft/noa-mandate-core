namespace NoaReceipt;

/// <summary>
/// The opt-in strict-bytes verifier profile. "native" (the default) verifies parsed values and never
/// judges the received encoding. "strict-bytes" additionally requires the ORIGINAL bytes of a bare
/// chain file to equal UTF8(Jcs.Canonicalize(parsed array)) — the complete array in presented order,
/// brackets and separators included — before any receipt check. Nothing is trimmed, BOM-stripped,
/// translated or repaired first: the decoder is UTF8Encoding(false, true), whose GetString keeps a BOM
/// as U+FEFF and throws on invalid bytes. A mismatch is MALFORMED with a detail starting
/// NON_CANONICAL_BYTES; equality hands the same parsed tree to the unchanged VerifyChain. The gate
/// (one snapshot of the caller's buffer) is StrictBytesGate.cs.
/// </summary>
public static partial class Verifier
{
    public const string ProfileNative = StrictBytesGate.ProfileNative;
    public const string ProfileStrictBytes = StrictBytesGate.ProfileStrictBytes;
    public const string NonCanonicalBytes = StrictBytesGate.NonCanonicalBytes;

    public static bool IsProfile(string? profile) => StrictBytesGate.IsProfile(profile);

    /// <summary>Strict decode + strict parse + (strict-bytes only) one whole-input comparison over one
    /// snapshot of <paramref name="data"/>. Returns the parsed tree, or null with the MALFORMED detail.</summary>
    public static JVal? AdmitChainBytes(byte[] data, string profile, out string detail) =>
        StrictBytesGate.Admit(data, profile, null, out detail);

    /// <summary>Byte-entry wrapper of VerifyChain: the same verdicts, plus the opt-in strict-bytes gate.
    /// The trust inputs are parsed values exactly as VerifyChain takes them; their rules are unchanged.</summary>
    public static VerifyResult VerifyChainBytes(byte[] data, JVal? keyringVal, JVal? identityVal, JVal? checkpointVal, string profile)
    {
        JVal? receipts = AdmitChainBytes(data, profile, out string detail);
        if (receipts is null) return new VerifyResult(VerifyStatus.Malformed, detail);
        return VerifyChain(receipts, keyringVal, identityVal, checkpointVal);
    }
}
