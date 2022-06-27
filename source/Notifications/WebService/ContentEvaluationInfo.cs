using System;

namespace OSIsoft.PISystemDeploymentTests
{
#pragma warning disable SA1600 // Elements should be documented
    internal class ContentEvaluationInfo
    {
        public Guid Id { get; set; }

        public string Name { get; set; } = string.Empty;

        public int PropertyId { get; set; }
    }
#pragma warning restore SA1600 // Elements should be documented
}
