using System;

namespace OSIsoft.PISystemDeploymentTests
{
#pragma warning disable SA1600 // Elements should be documented
    internal sealed class Subscribers
    {
        public string Name { get; set; }

        public string Configuration { get; set; }

        public string Type { get; set; }

        public DateTime SendTime { get; set; }

        public string SendStatus { get; set; }

        public int RetryCount { get; set; }
    }
#pragma warning restore SA1600 // Elements should be documented
}
