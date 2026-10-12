using K9.Api.Assessments;

namespace K9.Api.Tests.Assessments;

/// <summary>
/// The lifecycle as a pure function of an identity's observation history. FAIL (muted or
/// not) and an unmuted PASS are conclusive; the latest conclusive observation decides.
/// </summary>
public sealed class FindingLifecycleTests
{
    private static readonly DateTimeOffset Day0 = new(2026, 9, 1, 10, 0, 0, TimeSpan.Zero);

    private static ObservationFact At(long id, int day, CheckResult result, bool muted = false) =>
        new(id, Day0.AddDays(day), result, muted);

    private static DateTimeOffset D(int day) => Day0.AddDays(day);

    public sealed record Case(string Name, ObservationFact[] History, FindingState? Expected)
    {
        public override string ToString() => Name;
    }

    public static TheoryData<Case> Cases => new()
    {
        new("no observations", [], null),
        new("PASS baseline is not a finding", [At(1, 0, CheckResult.Pass)], null),
        new("MANUAL alone is not a finding", [At(1, 0, CheckResult.Manual)], null),
        new("MUTED alone is not a finding", [At(1, 0, CheckResult.Muted)], null),
        new("first FAIL opens", [At(1, 0, CheckResult.Fail)],
            new(FindingStatus.Open, 1, 1, D(0), null, Reopened: false, NeedsReview: false, MutedInSource: false)),
        new("a muted FAIL still opens", [At(1, 0, CheckResult.Fail, muted: true)],
            new(FindingStatus.Open, 1, 1, D(0), null, false, false, MutedInSource: true)),
        new("newer FAIL keeps it open and becomes decisive", [At(1, 0, CheckResult.Fail), At(2, 7, CheckResult.Fail)],
            new(FindingStatus.Open, 2, 2, D(0), null, false, false, false)),
        new("newer PASS fixes", [At(1, 0, CheckResult.Fail), At(2, 7, CheckResult.Pass)],
            new(FindingStatus.Fixed, 2, 2, D(0), D(7), false, false, false)),
        new("newer muted PASS does not fix", [At(1, 0, CheckResult.Fail), At(2, 7, CheckResult.Pass, muted: true)],
            new(FindingStatus.Open, 1, 2, D(0), null, false, NeedsReview: true, MutedInSource: true)),
        new("newer MANUAL does not fix", [At(1, 0, CheckResult.Fail), At(2, 7, CheckResult.Manual)],
            new(FindingStatus.Open, 1, 2, D(0), null, false, NeedsReview: true, false)),
        new("newer MUTED does not fix", [At(1, 0, CheckResult.Fail), At(2, 7, CheckResult.Muted)],
            new(FindingStatus.Open, 1, 2, D(0), null, false, NeedsReview: true, MutedInSource: true)),
        new("older PASS does not fix", [At(1, 0, CheckResult.Pass), At(2, 7, CheckResult.Fail)],
            new(FindingStatus.Open, 2, 2, D(7), null, Reopened: false, false, false)),
        new("FAIL after a fix reopens", [At(1, 0, CheckResult.Fail), At(2, 7, CheckResult.Pass), At(3, 14, CheckResult.Fail)],
            new(FindingStatus.Open, 3, 3, D(14), null, Reopened: true, false, false)),
        new("fixed again after reopening", [At(1, 0, CheckResult.Fail), At(2, 7, CheckResult.Pass), At(3, 14, CheckResult.Fail), At(4, 21, CheckResult.Pass)],
            new(FindingStatus.Fixed, 4, 4, D(14), D(21), Reopened: false, false, false)),
        new("MANUAL after a fix keeps it fixed but asks for review", [At(1, 0, CheckResult.Fail), At(2, 7, CheckResult.Pass), At(3, 14, CheckResult.Manual)],
            new(FindingStatus.Fixed, 2, 3, D(0), D(7), false, NeedsReview: true, false)),
        new("muted FAIL after a fix reopens", [At(1, 0, CheckResult.Fail), At(2, 7, CheckResult.Pass), At(3, 14, CheckResult.Fail, muted: true)],
            new(FindingStatus.Open, 3, 3, D(14), null, Reopened: true, false, MutedInSource: true)),
        new("non-conclusive history before the first FAIL is ignored", [At(1, 0, CheckResult.Manual), At(2, 7, CheckResult.Pass, muted: true), At(3, 14, CheckResult.Fail)],
            new(FindingStatus.Open, 3, 3, D(14), null, false, false, false)),
        new("open period starts at the first FAIL after the last PASS", [At(1, 0, CheckResult.Fail), At(2, 7, CheckResult.Pass), At(3, 14, CheckResult.Fail), At(4, 21, CheckResult.Manual), At(5, 28, CheckResult.Fail)],
            new(FindingStatus.Open, 5, 5, D(14), null, Reopened: true, false, false)),
    };

    [Theory]
    [MemberData(nameof(Cases))]
    public void Lifecycle_rules(Case c)
    {
        Assert.Equal(c.Expected, FindingLifecycle.Derive(c.History));
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void The_state_does_not_depend_on_the_order_observations_arrive_in(Case c)
    {
        var expected = FindingLifecycle.Derive(c.History);
        foreach (var permutation in Permutations(c.History))
        {
            Assert.Equal(expected, FindingLifecycle.Derive(permutation));
        }
    }

    [Fact]
    public void Two_observations_with_the_same_scan_time_are_refused()
    {
        // The database makes (identity, scan time) unique; a history breaking that is a bug,
        // and deciding anyway would pick a winner arbitrarily.
        ObservationFact[] history = [At(1, 0, CheckResult.Fail), At(2, 0, CheckResult.Pass)];
        Assert.Throws<ArgumentException>(() => FindingLifecycle.Derive(history));
        Assert.Throws<ArgumentException>(() => FindingLifecycle.Derive([At(1, 0, CheckResult.Fail), At(2, 0, CheckResult.Fail)]));
    }

    [Fact]
    public void Observation_IDs_do_not_influence_the_decision()
    {
        // IDs reflect import order. Only scan times may decide.
        var low = FindingLifecycle.Derive([At(1, 0, CheckResult.Fail), At(2, 7, CheckResult.Pass)]);
        var high = FindingLifecycle.Derive([At(2, 0, CheckResult.Fail), At(1, 7, CheckResult.Pass)]);
        Assert.Equal(FindingStatus.Fixed, low!.Status);
        Assert.Equal(low with { DecisiveObservationId = 1, LatestObservationId = 1 }, high);
    }

    private static IEnumerable<ObservationFact[]> Permutations(ObservationFact[] items)
    {
        if (items.Length <= 1)
        {
            yield return items;
            yield break;
        }
        for (var i = 0; i < items.Length; i++)
        {
            var rest = items.Where((_, j) => j != i).ToArray();
            foreach (var tail in Permutations(rest))
            {
                yield return [items[i], .. tail];
            }
        }
    }
}
