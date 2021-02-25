using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using OSIsoft.AF.PI;

namespace OSIsoft.PISystemDeploymentTests.PIDA
{
	/// <summary>
	/// This is a test fact attribute
	/// </summary>
	public sealed class PICollectiveFactAttribute : OptionalFactAttribute
	{
		/// <summary>
		/// This is a test fact attribute
		/// </summary>
		/// <param name="fixture"> need a PIFixture </param>
		public PICollectiveFactAttribute() : base(PICollectiveTests.KeySetting, PICollectiveTests.KeySettingTypeCode)
		{
            // Return if the Skip property has been changed in the base constructor
            if (!string.IsNullOrEmpty(Skip))
                return;

			try
			{
				var piDataArchiveName = Settings.PIDataArchive;
				var piServers = PIServers.GetPIServers();
				var myPIServer = piServers[piDataArchiveName];

				if (myPIServer.Collective != null)
					return;

				Skip = $"Test skipped due to the PI Server not being a PI Collective";
			}
			catch (Exception e)
			{
				Skip = $"Test skipped due to an unhandled exception: {e.Message}";
			}
        }
	}
}
