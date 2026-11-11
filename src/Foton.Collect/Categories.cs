using System;
using System.Collections.Generic;
using System.Linq;
using Foton.Core;

namespace Foton.Collect
{
    /// <summary>One collection category: its CaseCategories key and the method that runs its tasks.</summary>
    public sealed class CollectCategory
    {
        public CollectCategory(string key, Action<FotonSession> run) { Key = key; Run = run; }
        /// <summary>The CaseCategories key (System, Users, Processes, ...).</summary>
        public string Key { get; }
        public Action<FotonSession> Run { get; }
    }

    /// <summary>
    /// Categories in the 1.38.x run order (Invoke-FotonTriage): Processes, Network, Users, System, Persistence, Security,
    /// Software, EventLogs, Filesystem. Volatile state comes first so the collector's own activity disturbs it least.
    /// To add a category, add a static class with a Run(FotonSession) method that calls TaskRunner.Run per task, and
    /// list it here in that order.
    /// </summary>
    public static class Categories
    {
        public static readonly IReadOnlyList<CollectCategory> InOrder = new[]
        {
            new CollectCategory("Processes", ProcessCollection.Run),
            new CollectCategory("Network", NetworkCollection.Run),
            new CollectCategory("Users", UserCollection.Run),
            new CollectCategory("System", SystemCollection.Run),
            new CollectCategory("Persistence", PersistenceCollection.Run),
            new CollectCategory("Security", SecurityCollection.Run),
            new CollectCategory("Software", SoftwareCollection.Run),
            new CollectCategory("EventLogs", EventLogCollection.Run),
            new CollectCategory("Filesystem", FilesystemCollection.Run),
        };
    }
}
