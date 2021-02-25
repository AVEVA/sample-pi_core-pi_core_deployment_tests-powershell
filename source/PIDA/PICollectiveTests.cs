using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using OSIsoft.AF.PI;
using OSIsoft.AF.Time;
using PISDK;
using Xunit;
using Xunit.Abstractions;

namespace OSIsoft.PISystemDeploymentTests.PIDA
{
	/// <summary>
	/// This class tests the PI Collective status
	/// </summary>
	public class PICollectiveTests : IClassFixture<PIFixture>
	{
		internal const string KeySetting = "PIDataArchive";
		internal const TypeCode KeySettingTypeCode = TypeCode.String;
		
		/// <summary>
		/// test
		/// </summary>
		/// <param name="output">test</param>
		/// <param name="fixture">test</param>
		public PICollectiveTests(ITestOutputHelper output, PIFixture fixture)
		{
			Output = output;
			Fixture = fixture;
		}

		private ITestOutputHelper Output { get; }
		private PIFixture Fixture { get; }

		/// <summary>
		/// test
		/// </summary>
		[PICollectiveFact]
		public void CollectiveFlagShouldExist() => Assert.NotNull(Fixture.PIServer.Collective);
		
		/// <summary>
		/// test
		/// </summary>
		[PICollectiveFact]
		public void PICollectiveIsInSync()
		{
			PISDK.PISDK pisdk = new PISDK.PISDK();
			Server myPIDA = pisdk.Servers[Settings.PIDataArchive];
			myPIDA.Open();
			IPICollective myPICollective = (IPICollective)myPIDA;
			Assert.Equal(0, myPICollective.CollectiveStatus);
			myPIDA.Close();
		}

		/// <summary>
		/// Test
		/// </summary>
		[PICollectiveFact]
		public void SucessfullConnectionToEachPICollectiveMembers()
		{
			PICollective myPICollective = Fixture.PIServer.Collective;
			foreach (var member in myPICollective.Members)
			{
				try
				{
					member.Connect();
					Output.WriteLine($"Connection Successful for {member.Name}");
				}
				catch (Exception e)
				{
					Output.WriteLine($"Connection failed with error: {e.Message}, for member {member.Name}");
				}
				finally
				{
					Assert.True(member.IsConnected);
				}
			}				
		}

		/// <summary>
		/// test
		/// </summary>
		[PICollectiveFact]
		public void PICollectiveIsRunningNormallyPerformanceCounterCheck()
		{
			var myPICollective = Fixture.PIServer.Collective;
			var myPerformanceCounter = new PerformanceCounter("PI Collective Statistics", "Is Running Normally", myPICollective.PIServer.Name, myPICollective.Members[0].Name);
			Assert.Equal(1, myPerformanceCounter.RawValue);
			myPerformanceCounter.Dispose();
		}

		/// <summary>
		/// test
		/// </summary>
		[PICollectiveFact]
		public void PICollectiveNumberOfMemberPerformanceCounterCheck()
		{
			var myPICollective = Fixture.PIServer.Collective;
			var myPerformanceCounter = new PerformanceCounter("PI Collective Statistics", "Number of Servers", myPICollective.PIServer.Name, myPICollective.Members[0].Name);
			Assert.Equal(myPerformanceCounter.RawValue, myPICollective.Members.Count);
			myPerformanceCounter.Dispose();
		}
	}
}
