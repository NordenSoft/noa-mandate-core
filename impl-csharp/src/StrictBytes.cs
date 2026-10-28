using System.Text;

namespace NoaReceipt;

/// <summary>
/// The opt-in strict-bytes verifier profile. "native" (the default) verifies parsed values and never
/// judges the received encoding. "strict-bytes" additionally requires the ORIGINAL bytes of a bare
/// chain file to equal UTF8(Jcs.Canonicalize(parsed array)) — the complete array in presented order,
/// brackets and separators included — before any receipt check. Nothing is trimmed, BOM-stripped,
/// translated or repaired first: the decoder is UTF8Encoding(false, true), whose GetString keeps a BOM
/// as U+FEFF and throws on invalid bytes. A mismatch is MALFORMED with a detail starting
/// NON_CANONICAL_BYTES; equality hands the same parsed tree to the unchanged VerifyChain.
/// </summary>
public static partial class Verifier
{
    public const string ProfileNative = "native";
    public const string ProfileStrictBytes = "strict-bytes";
    public const string NonCanonicalBytes = "NON_CANONICAL_BYTES";

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public static bool IsProfile(string? profile) => profile == ProfileNative || profile == ProfileStrictBytes;

    /// <summary>Strict decode + strict parse + (strict-bytes only) one whole-input comparison. Returns
    /// the parsed tree, or null with the MALFORMED detail of the refusal in <paramref name="detail"/>.</summary>
    public static JVal? AdmitChainBytes(byte[] data, string profile, out string detail)
    {
        detail = "";
        if (!IsProfile(profile))
        {
            detail = "profile must be native or strict-bytes";
            return null;
        }
        string text;
        try
        {
            text = StrictUtf8.GetString(data);
        }
        catch (DecoderFallbackException)
        {
            detail = "input is not valid UTF-8";
            return null;
        }
        JVal value;
        try
        {
            value = StrictJson.Parse(text);
        }
        catch (Exception e)
        {
            detail = e.Message;
            return null;
        }
        if (profile == ProfileStrictBytes)
        {
            byte[] canonical;
            try
            {
                canonical = StrictUtf8.GetBytes(Jcs.Canonicalize(value));
            }
            catch (Exception)
            {
                detail = NonCanonicalBytes + ": receipts: the parsed input has no JCS serialization";
                return null;
            }
            if (!canonical.AsSpan().SequenceEqual(data.AsSpan()))
            {
                detail = NonCanonicalBytes + ": receipts: the input bytes are not the UTF-8 JCS serialization of the parsed chain";
                return null;
            }
        }
        return value;
    }

    /// <summary>Byte-entry wrapper of VerifyChain: the same verdicts, plus the opt-in strict-bytes gate.
    /// The trust inputs are parsed values exactly as VerifyChain takes them; their rules are unchanged.</summary>
    public static VerifyResult VerifyChainBytes(byte[] data, JVal? keyringVal, JVal? identityVal, JVal? checkpointVal, string profile)
    {
        JVal? receipts = AdmitChainBytes(data, profile, out string detail);
        if (receipts is null) return new VerifyResult(VerifyStatus.Malformed, detail);
        return VerifyChain(receipts, keyringVal, identityVal, checkpointVal);
    }
}
