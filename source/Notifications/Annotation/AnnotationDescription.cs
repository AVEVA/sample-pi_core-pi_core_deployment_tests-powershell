using System.Collections.Generic;

namespace OSIsoft.PISystemDeploymentTests
{
#pragma warning disable SA1600 // Elements should be documented
    internal sealed class AnnotationDescription
    {
        public string Notification { get; set; }

        public List<Subscribers> Subscribers { get; set; }
    }
#pragma warning restore SA1600 // Elements should be documented
}
