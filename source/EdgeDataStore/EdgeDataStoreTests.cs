using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;

namespace OSIsoft.PISystemDeploymentTests
{
	/// <summary>
	/// This class tests various features of the Edge Data Store
	/// </summary>
	public class EdgeDataStoreTests : IClassFixture<EdgeDataStoreFixture>
	{
		internal const string KeySetting = "EdgeDataStoreTests";
		internal const TypeCode KeySettingTypeCode = TypeCode.String;
		internal const string PortSetting = "EdgeDataStorePort";

		/// <summary>
		/// This is a summary 
		/// </summary>
		/// <param name="output">output console</param>
		/// <param name="fixture">fixture</param>
		public EdgeDataStoreTests(ITestOutputHelper output, EdgeDataStoreFixture fixture)
		{
			Output = output;
			Fixture = fixture;
		}

		private EdgeDataStoreFixture Fixture { get; }
		private ITestOutputHelper Output { get; }

		/// <summary>
		/// This is documented
		/// </summary>
        [OptionalFact(KeySetting, KeySettingTypeCode)]
		public void ConfigurationTest()
		{
			string url = "configuration";
			Output.WriteLine($"Verifying the EDS configuration can be retrieved from {Fixture.Client.BaseAddress}{url}.");
			string content = Fixture.Client.DownloadString(url);
			Assert.True(!string.IsNullOrEmpty(content), "Failed to get local EDS configuration.");
		}		

		/// <summary>
		/// Verifies EDS REST endpoints return a response
		/// </summary>
		/// <param name="path">The REST endpoints to verify</param>
		[OptionalTheory(KeySetting, KeySettingTypeCode)]
		[InlineData("configuration")]
		public void EndpointsTest(string path)
		{
			Output.WriteLine($"Verifying the EDS configuration can be retrieved from {Fixture.Client.BaseAddress}{path}.");
			string content = Fixture.Client.DownloadString(path);
			Assert.True(!string.IsNullOrEmpty(content), "Failed to get local EDS configuration.");
		}
	}
}
