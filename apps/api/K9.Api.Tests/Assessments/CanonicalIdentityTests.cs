using System.Security.Cryptography;
using System.Text;
using K9.Api.Assessments;
using K9.Api.Tests.Infrastructure;
using static K9.Api.Tests.Infrastructure.ProwlerFixtures;

namespace K9.Api.Tests.Assessments;

/// <summary>
/// Identity = organization + provider + account + check + location + resource uid + resource
/// name. Prowler's finding UID is never part of it.
/// </summary>
public sealed class CanonicalIdentityTests
{
    private static readonly Guid Acme = Guid.Parse("0199d0a1-0000-7000-8000-000000000001");
    private static readonly Guid Globex = Guid.Parse("0199d0a1-0000-7000-8000-000000000002");

    public static TheoryData<string, Func<CanonicalIdentity, CanonicalIdentity>> SingleComponentChanges => new()
    {
        { "organization", i => i with { OrganizationId = Globex } },
        { "provider", i => i with { Provider = "azure" } },
        { "account", i => i with { AccountUid = AccountB } },
        { "check", i => i with { CheckId = RootMfaCheck } },
        { "location", i => i with { Location = "us-east-1" } },
        { "resource uid", i => i with { ResourceUid = "arn:aws:s3:::k9-other" } },
        { "resource name", i => i with { ResourceName = "k9-other" } },
    };

    [Theory]
    [MemberData(nameof(SingleComponentChanges))]
    public void Every_component_distinguishes_identities(string component, Func<CanonicalIdentity, CanonicalIdentity> change)
    {
        var identity = CanonicalIdentity.For(Acme, Observations.Sample());
        var changed = change(identity);

        Assert.NotEqual(identity.CanonicalKey, changed.CanonicalKey);
        Assert.False(identity.Hash.AsSpan().SequenceEqual(changed.Hash), $"changing the {component} kept the hash");
    }

    [Fact]
    public void Identity_ignores_everything_that_is_not_a_component()
    {
        var sample = Observations.Sample();
        var other = sample with
        {
            Index = 7, ScanTime = T3, Result = CheckResult.Pass, Muted = true, StatusDetail = "different", SeverityId = 1,
            ProwlerFindingUid = "prowler-something-else", ProwlerScanId = null, Title = "x", ProwlerVersion = "9.9.9",
        };

        Assert.Equal(CanonicalIdentity.For(Acme, sample).CanonicalKey, CanonicalIdentity.For(Acme, other).CanonicalKey);
    }

    [Fact]
    public void The_encoding_is_unambiguous()
    {
        var sample = Observations.Sample();
        string[] tricky = ["a|b", "a", "b|c", "a\",\"b", "a\\", "\",\"", "]", "", " ", "naïve", "a\u0000b"];

        var keys = new HashSet<string>(StringComparer.Ordinal);
        var count = 0;
        foreach (var uid in tricky)
        {
            foreach (var name in tricky)
            {
                keys.Add(CanonicalIdentity.For(Acme, sample with { ResourceUid = uid, ResourceName = name }).CanonicalKey);
                count++;
            }
        }
        Assert.Equal(count, keys.Count);
    }

    [Fact]
    public void The_hash_is_SHA256_of_the_canonical_key()
    {
        var identity = CanonicalIdentity.For(Acme, Observations.Sample());
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(identity.CanonicalKey)), identity.Hash);
        Assert.Equal(identity.CanonicalKey, CanonicalIdentity.For(Acme, Observations.Sample()).CanonicalKey);
    }

    // ---- Against real Prowler output ---------------------------------------------------

    [Fact]
    public async Task Two_access_keys_with_one_ARN_are_different_identities()
    {
        var keys = (await ReadValidAsync(BaselineA)).Where(o => o.CheckId == KeyRotationCheck).ToList();
        Assert.Equal(2, Keys(keys).Count);
    }

    [Fact]
    public async Task One_ARN_reported_in_two_regions_is_two_identities()
    {
        var ami = (await ReadValidAsync(BaselineA)).Where(o => o.CheckId == AmiBlockCheck).ToList();
        Assert.Single(ami.Select(a => a.ResourceUid).Distinct());
        Assert.Equal(2, Keys(ami).Count);
    }

    [Fact]
    public async Task Resources_sharing_a_Prowler_finding_uid_are_different_identities()
    {
        var colliding = await ReadValidAsync(UidCollision);
        Assert.Single(colliding.Select(o => o.ProwlerFindingUid).Distinct());
        Assert.Equal(2, Keys(colliding).Count);
    }

    [Fact]
    public async Task The_same_resource_ID_in_two_accounts_or_two_organizations_is_different_identities()
    {
        var inA = Assert.Single(await ReadValidAsync(BaselineA), o => o.ResourceName == "sg-0a1");
        var inB = Assert.Single(await ReadValidAsync(BaselineB), o => o.ResourceName == "sg-0a1");

        Assert.NotEqual(CanonicalIdentity.For(Acme, inA).CanonicalKey, CanonicalIdentity.For(Acme, inB).CanonicalKey);
        Assert.NotEqual(CanonicalIdentity.For(Acme, inA).CanonicalKey, CanonicalIdentity.For(Globex, inA).CanonicalKey);
    }

    [Fact]
    public async Task A_re_export_of_a_scan_has_exactly_the_same_identities()
    {
        Assert.Equal(Keys(await ReadValidAsync(FollowupA)), Keys(await ReadValidAsync(ReexportA)));
    }

    [Fact]
    public async Task Every_observation_in_a_scan_has_its_own_identity()
    {
        var baseline = await ReadValidAsync(BaselineA);
        Assert.Equal(baseline.Count, Keys(baseline).Count);
    }

    private static SortedSet<string> Keys(IEnumerable<ParsedObservation> observations) =>
        new(observations.Select(o => CanonicalIdentity.For(Acme, o).CanonicalKey), StringComparer.Ordinal);
}
