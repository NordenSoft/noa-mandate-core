using System.Text;

namespace NoaReceipt;

/// <summary>
/// The strict-bytes gate itself, kept free of the verifier so impl-csharp/selfcheck can compile it
/// with only Json.cs and Jcs.cs. Verifier (StrictBytes.cs) is the public entry and delegates here.
///
/// ONE SNAPSHOT (security round 1, finding 1): the caller's byte[] is mutable and may be shared with
/// another thread, so it is copied exactly once on entry and the decode, the parse and the comparison
/// all read that private copy. A swap of the caller's bytes after the copy cannot pair one parse tree
/// with different compared bytes.
/// </summary>
public static class StrictBytesGate
{
    public const string ProfileNative = "native";
    public const string ProfileStrictBytes = "strict-bytes";
    public const string NonCanonicalBytes = "NON_CANONICAL_BYTES";

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public static bool IsProfile(string? profile) => profile == ProfileNative || profile == ProfileStrictBytes;

    /// <summary>Snapshot + strict decode + strict parse + (strict-bytes only) one whole-input comparison.
    /// Returns the parsed tree, or null with the MALFORMED detail in <paramref name="detail"/>.
    /// <paramref name="afterParse"/> runs between the parse and the comparison; production passes null,
    /// the self-check uses it to rewrite the caller's buffer inside that window.</summary>
    public static JVal? Admit(byte[] data, string profile, Action? afterParse, out string detail)
    {
        detail = "";
        if (!IsProfile(profile))
        {
            detail = "profile must be native or strict-bytes";
            return null;
        }
        if (data is null)
        {
            detail = "chain input must be the original bytes";
            return null;
        }
        byte[] snapshot = (byte[])data.Clone();
        string text;
        try
        {
            text = StrictUtf8.GetString(snapshot);
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
        afterParse?.Invoke();
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
            if (!canonical.AsSpan().SequenceEqual(snapshot.AsSpan()))
            {
                detail = NonCanonicalBytes + ": receipts: the input bytes are not the UTF-8 JCS serialization of the parsed chain";
                return null;
            }
        }
        return value;
    }
}
