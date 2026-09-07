using System.Numerics;
using System.Text.Json.Serialization;

namespace NoaReceipt;

public sealed class HistoricalEvidence
{
    [JsonPropertyName("retirement")] public string Retirement { get; init; } = "NOT_PROVIDED";
    [JsonPropertyName("witness")] public string Witness { get; init; } = "NOT_PROVIDED";
    [JsonPropertyName("availability")] public string Availability { get; init; } = "NOT_PROVIDED";
}

public sealed class HistoricalDimensions
{
    [JsonPropertyName("integrity")] public string Integrity { get; init; } = "UNANSWERED";
    [JsonPropertyName("completeness")] public string Completeness { get; init; } = "UNANSWERED";
    [JsonPropertyName("attribution")] public string Attribution { get; init; } = "UNATTRIBUTABLE";
    [JsonPropertyName("organizationalIndependence")] public string OrganizationalIndependence { get; init; } = "UNVERIFIED";
    [JsonPropertyName("evidence")] public HistoricalEvidence Evidence { get; init; } = new();
}

public sealed class HistoricalPolicy
{
    [JsonPropertyName("verifierVersion")] public string VerifierVersion { get; init; } = HistoricalVerifier.Spec;
    [JsonPropertyName("purpose")] public string Purpose { get; init; } = "historical-audit";
}

public sealed class HistoricalResult
{
    [JsonPropertyName("spec")] public string Spec { get; init; } = HistoricalVerifier.Spec;
    [JsonPropertyName("policy")] public HistoricalPolicy Policy { get; init; } = new();
    [JsonPropertyName("classification")] public string Classification { get; init; } = "INVALID";
    [JsonPropertyName("code")] public string Code { get; init; } = "RECEIPT_MALFORMED";
    [JsonPropertyName("dimensions")] public HistoricalDimensions Dimensions { get; init; } = new();
    [JsonPropertyName("chain")] public string? Chain { get; init; }
    [JsonPropertyName("count")] public int Count { get; init; }
    [JsonPropertyName("attributedThroughSeq")] public long? AttributedThroughSeq { get; init; }
    [JsonPropertyName("asOf")] public string? AsOf { get; init; }
}

public static class HistoricalVerifier
{
    public const string Spec = "noa.historical-verification/0.1";
    private const string LifecycleSpec = "noa.signing-key-lifecycle/0.1";

    private sealed class HistoricalTrust
    {
        public required JObj Keyring { get; init; }
        public required Dictionary<string, bool> Retired { get; init; }
        public required Dictionary<string, BigInteger?> ValidFrom { get; init; }
        public required Dictionary<string, BigInteger?> RetiredAt { get; init; }
        public required bool Lifecycle { get; init; }
    }

    private static HistoricalDimensions Dimensions(
        string integrity,
        string completeness,
        string attribution,
        string retirement,
        string witness,
        string availability) => new()
    {
        Integrity = integrity,
        Completeness = completeness,
        Attribution = attribution,
        OrganizationalIndependence = "UNVERIFIED",
        Evidence = new HistoricalEvidence
        {
            Retirement = retirement,
            Witness = witness,
            Availability = availability,
        },
    };

    private static HistoricalResult Result(
        string classification,
        string code,
        HistoricalDimensions dimensions,
        string? chain,
        int count,
        long? attributedThroughSeq = null,
        string? asOf = null) => new()
    {
        Classification = classification,
        Code = code,
        Dimensions = dimensions,
        Chain = chain,
        Count = count,
        AttributedThroughSeq = attributedThroughSeq,
        AsOf = asOf,
    };

    private static long Decimal(string s, int start, int length)
    {
        long value = 0;
        for (int i = start; i < start + length; i++) value = value * 10 + (s[i] - '0');
        return value;
    }

    private static long DaysFromCivil(long year, long month, long day)
    {
        year -= month <= 2 ? 1 : 0;
        long era = year >= 0 ? year / 400 : (year - 399) / 400;
        long yoe = year - era * 400;
        long mp = month + (month > 2 ? -3 : 9);
        long doy = (153 * mp + 2) / 5 + day - 1;
        long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        return era * 146097 + doe - 719468;
    }

    /// UTC nanoseconds. Leap-second checkpoints return null, matching the TypeScript Date.parse gate.
    private static BigInteger? ParseInstant(string value)
    {
        if (!Schema.Rfc3339Instant(value)) return null;
        long second = Decimal(value, 17, 2);
        if (second > 59) return null;
        long year = Decimal(value, 0, 4), month = Decimal(value, 5, 2), day = Decimal(value, 8, 2);
        long hour = Decimal(value, 11, 2), minute = Decimal(value, 14, 2);
        int index = 19;
        BigInteger nanos = BigInteger.Zero;
        if (value[index] == '.')
        {
            int start = ++index;
            while (index < value.Length && value[index] >= '0' && value[index] <= '9') index++;
            long fraction = Decimal(value, start, index - start);
            nanos = fraction * BigInteger.Pow(10, 9 - (index - start));
        }
        long offsetSeconds = 0;
        if (value[index] != 'Z' && value[index] != 'z')
        {
            long sign = value[index] == '+' ? 1 : -1;
            offsetSeconds = sign * (Decimal(value, index + 1, 2) * 3600 + Decimal(value, index + 4, 2) * 60);
        }
        long seconds = DaysFromCivil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second - offsetSeconds;
        return new BigInteger(seconds) * 1_000_000_000 + nanos;
    }

    private static HistoricalTrust? ParseKeyring(JVal document)
    {
        if (document is not JObj root) return null;
        bool looksLifecycle = root.Get("spec") is JStr spec && spec.Value == LifecycleSpec
            || root.Has("keys") && root.Get("keys") is not JStr;
        if (!looksLifecycle)
        {
            var flat = new JObj();
            foreach (string kid in root.Keys)
            {
                if (kid.Length == 0 || root.Get(kid) is not JStr publicKey || publicKey.Value.Length == 0) return null;
                flat.Add(kid, new JStr(publicKey.Value));
            }
            return new HistoricalTrust
            {
                Keyring = flat,
                Retired = new Dictionary<string, bool>(StringComparer.Ordinal),
                ValidFrom = new Dictionary<string, BigInteger?>(StringComparer.Ordinal),
                RetiredAt = new Dictionary<string, BigInteger?>(StringComparer.Ordinal),
                Lifecycle = false,
            };
        }
        if (root.Keys.Count != 2 || root.Get("spec") is not JStr lifecycleSpec || lifecycleSpec.Value != LifecycleSpec
            || root.Get("keys") is not JObj entries || entries.Keys.Count == 0) return null;
        var result = new HistoricalTrust
        {
            Keyring = new JObj(),
            Retired = new Dictionary<string, bool>(StringComparer.Ordinal),
            ValidFrom = new Dictionary<string, BigInteger?>(StringComparer.Ordinal),
            RetiredAt = new Dictionary<string, BigInteger?>(StringComparer.Ordinal),
            Lifecycle = true,
        };
        foreach (string kid in entries.Keys)
        {
            if (kid.Length == 0 || entries.Get(kid) is not JObj entry || (entry.Keys.Count != 2 && entry.Keys.Count != 3)
                || !entry.Has("publicKey") || !entry.Has("retiredAt")
                || (entry.Keys.Count == 3 && !entry.Has("validFrom"))
                || entry.Get("publicKey") is not JStr publicKey || publicKey.Value.Length == 0) return null;
            result.Keyring.Add(kid, new JStr(publicKey.Value));
            if (!entry.Has("validFrom") || entry.Get("validFrom") is JNull)
            {
                result.ValidFrom[kid] = null;
            }
            else if (entry.Get("validFrom") is JStr validFrom && ParseInstant(validFrom.Value) is BigInteger activation)
            {
                result.ValidFrom[kid] = activation;
            }
            else return null;
            if (entry.Get("retiredAt") is JNull)
            {
                result.RetiredAt[kid] = null;
            }
            else if (entry.Get("retiredAt") is JStr retiredAt && ParseInstant(retiredAt.Value) is BigInteger instant)
            {
                result.Retired[kid] = true;
                result.RetiredAt[kid] = instant;
            }
            else return null;
            if (result.ValidFrom[kid].HasValue && result.RetiredAt[kid].HasValue
                && result.ValidFrom[kid]!.Value >= result.RetiredAt[kid]!.Value) return null;
        }
        return result;
    }

    public static HistoricalResult Verify(
        JVal receiptsValue,
        JVal receiptRoot,
        JVal? checkpointValue,
        JVal? checkpointRoot,
        JVal? identity)
    {
        string witness = checkpointValue is null ? "NOT_PROVIDED" : "PROVIDED";
        string availability = checkpointValue is null ? "NOT_PROVIDED" : "AVAILABLE";
        JArr? receiptArray = receiptsValue as JArr;
        int count = receiptArray?.Items.Count ?? 0;
        string? chain = receiptArray?.Items.FirstOrDefault() is JObj first
            && first.Get("scope") is JObj scope && scope.Get("chain") is JStr chainString ? chainString.Value : null;
        HistoricalTrust? receiptTrust = ParseKeyring(receiptRoot);
        if (receiptTrust is null)
            return Result("INVALID", "RECEIPT_ROOT_INVALID", Dimensions("UNANSWERED", "UNANSWERED", "UNATTRIBUTABLE", "NOT_PROVIDED", witness, availability), null, 0);
        string retirement = receiptTrust.Lifecycle ? "PROVIDED" : "NOT_PROVIDED";

        // CONTROL G2-RETIREMENT-INTEGRITY-CSHARP: retained keys reach only the unchanged chain
        // verifier without a checkpoint. Current-use authorization never receives this projection.
        VerifyResult receiptResult = Verifier.VerifyChain(receiptsValue, receiptTrust.Keyring, identity, null);
        if (receiptResult.Status != VerifyStatus.Valid)
        {
            if (receiptResult.Status == VerifyStatus.Tampered)
                return Result("INVALID", "RECEIPT_INTEGRITY_FAILURE", Dimensions("BROKEN", "UNANSWERED", "UNATTRIBUTABLE", retirement, witness, availability), chain, count);
            if (receiptResult.Status == VerifyStatus.Untrusted)
                return Result("INVALID", "RECEIPT_IDENTITY_UNTRUSTED", Dimensions("UNANSWERED", "UNANSWERED", "UNATTRIBUTABLE", retirement, witness, availability), chain, count);
            return Result("INVALID", "RECEIPT_MALFORMED", Dimensions("UNANSWERED", "UNANSWERED", "UNATTRIBUTABLE", retirement, witness, availability), chain, count);
        }

        var receipts = ((JArr)receiptsValue).Items.Cast<JObj>().ToList();
        var bySeq = receipts.ToDictionary(
            receipt => ((JInt)((JObj)receipt.Get("chain")!).Get("seq")!).Value,
            receipt => receipt);
        JObj head = bySeq[receipts.Count - 1];
        if (checkpointValue is null)
            return Result("UNVERIFIED", "NO_WITNESS", Dimensions("INTACT", "UNANSWERED", "UNATTRIBUTABLE", retirement, "NOT_PROVIDED", "NOT_PROVIDED"), chain, count);
        if (checkpointRoot is null)
            return Result("UNVERIFIED", "WITNESS_ROOT_NOT_PROVIDED", Dimensions("UNANSWERED", "UNANSWERED", "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count);
        HistoricalTrust? witnessTrust = ParseKeyring(checkpointRoot);
        if (witnessTrust is null)
            return Result("UNVERIFIED", "WITNESS_ROOT_INVALID", Dimensions("UNANSWERED", "UNANSWERED", "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count);
        if (!Verifier.CheckpointShapeOk(checkpointValue))
            return Result("INVALID", "WITNESS_MALFORMED", Dimensions("BROKEN", "UNANSWERED", "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count);
        Verifier.CpVerdict cpVerdict = Verifier.VerifyCheckpoint(checkpointValue, witnessTrust.Keyring);
        if (cpVerdict == Verifier.CpVerdict.Unverified)
            return Result("UNVERIFIED", "WITNESS_KEY_NOT_TRUSTED", Dimensions("UNANSWERED", "UNANSWERED", "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count);
        if (cpVerdict != Verifier.CpVerdict.Ok)
            return Result("INVALID", "WITNESS_INTEGRITY_FAILURE", Dimensions("BROKEN", "UNANSWERED", "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count);

        var checkpoint = (JObj)checkpointValue;
        var checkpointSig = (JObj)checkpoint.Get("sig")!;
        string witnessKid = ((JStr)checkpointSig.Get("kid")!).Value;
        string witnessPublic = ((JStr)witnessTrust.Keyring.Get(witnessKid)!).Value;
        byte[] witnessMaterial;
        try { witnessMaterial = Crypto.SpkiToRaw(witnessPublic); }
        catch { return Result("UNVERIFIED", "WITNESS_ROOT_INVALID", Dimensions("UNANSWERED", "UNANSWERED", "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count); }

        // CONTROL G2-WITNESS-KEY-SEPARATION-CSHARP: compare decoded key material, not kid labels.
        foreach (JObj receipt in receipts)
        {
            string receiptKid = ((JStr)((JObj)receipt.Get("sig")!).Get("kid")!).Value;
            string receiptPublic = ((JStr)receiptTrust.Keyring.Get(receiptKid)!).Value;
            if (witnessKid == receiptKid || witnessMaterial.AsSpan().SequenceEqual(Crypto.SpkiToRaw(receiptPublic)))
                return Result("UNVERIFIED", "WITNESS_KEY_NOT_SEPARATE", Dimensions("INTACT", "UNANSWERED", "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count);
        }
        if (witnessTrust.Retired.ContainsKey(witnessKid))
            return Result("UNVERIFIED", "WITNESS_KEY_RETIRED", Dimensions("INTACT", "UNANSWERED", "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count);

        string checkpointChain = ((JStr)checkpoint.Get("chain")!).Value;
        if (checkpointChain != chain)
            return Result("CONFLICT", "CHECKPOINT_CONFLICT", Dimensions("INTACT", "CONFLICT", "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count);
        long checkpointSeq = ((JInt)checkpoint.Get("highestSeq")!).Value;
        long headSeq = ((JInt)((JObj)head.Get("chain")!).Get("seq")!).Value;
        if (checkpointSeq > headSeq)
            return Result("CONFLICT", "CHECKPOINT_AHEAD", Dimensions("INTACT", "CONFLICT", "UNATTRIBUTABLE", retirement, "PROVIDED", "MISSING_RELATIVE_TO_CHECKPOINT"), chain, count);
        string checkpointHash = ((JStr)checkpoint.Get("headHash")!).Value;
        if (!bySeq.TryGetValue(checkpointSeq, out JObj? checkpointed)
            || ((JStr)((JObj)checkpointed.Get("chain")!).Get("hash")!).Value != checkpointHash)
            return Result("CONFLICT", "CHECKPOINT_CONFLICT", Dimensions("INTACT", "CONFLICT", "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count);

        string completeness = checkpointSeq == headSeq ? "HEAD_ANCHORED" : "PREFIX_ANCHORED";
        string checkpointTimeText = ((JStr)checkpoint.Get("ts")!).Value;
        BigInteger? checkpointTime = ParseInstant(checkpointTimeText);
        bool checkpointBeforeActivation = witnessTrust.ValidFrom.TryGetValue(witnessKid, out BigInteger? witnessValidFrom)
            && witnessValidFrom.HasValue
            && (!checkpointTime.HasValue || checkpointTime.Value < witnessValidFrom.Value);
        bool checkpointAfterRetirement = !checkpointTime.HasValue;
        for (long seq = 0; seq <= checkpointSeq; seq++)
        {
            string receiptKid = ((JStr)((JObj)bySeq[seq].Get("sig")!).Get("kid")!).Value;
            if (receiptTrust.ValidFrom.TryGetValue(receiptKid, out BigInteger? validFrom) && validFrom.HasValue
                && (!checkpointTime.HasValue || checkpointTime.Value < validFrom.Value)) checkpointBeforeActivation = true;
            if (receiptTrust.RetiredAt.TryGetValue(receiptKid, out BigInteger? retiredAt) && retiredAt.HasValue
                && (!checkpointTime.HasValue || checkpointTime.Value >= retiredAt.Value)) checkpointAfterRetirement = true;
        }
        if (checkpointBeforeActivation)
            return Result("UNVERIFIED", "CHECKPOINT_BEFORE_ACTIVATION", Dimensions("INTACT", completeness, "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count);
        if (checkpointAfterRetirement)
            return Result("UNVERIFIED", "CHECKPOINT_AFTER_RETIREMENT", Dimensions("INTACT", completeness, "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count);

        return Result(
            completeness == "HEAD_ANCHORED" ? "VERIFIED" : "PARTIAL",
            completeness,
            Dimensions("INTACT", completeness, "ATTRIBUTABLE_AS_OF", retirement, "PROVIDED", "AVAILABLE"),
            chain,
            count,
            checkpointSeq,
            checkpointTimeText);
    }
}
