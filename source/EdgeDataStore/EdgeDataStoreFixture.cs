using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace OSIsoft.PISystemDeploymentTests
{
	/// <summary>
	/// EDS Fixture
	/// </summary>
	public sealed class EdgeDataStoreFixture : IDisposable
	{
		/// <summary>
		/// Creates an instance of the Edge Data Store Fixture
		/// </summary>
		public EdgeDataStoreFixture()
		{
			Client.Headers.Add(HttpRequestHeader.ContentType, "application/jsonl charset=utf-8");
			Client.BaseAddress = $"http://localhost:{Settings.EdgeDataStorePort}/api/v1/";
		}

		/// <summary>
		/// The WebClient used to for REST endpoint calls.
		/// </summary>
		public WebClient Client { get; private set; } = new WebClient();

		/// <summary>
		/// Clean up when tests are finished
		/// </summary>
		public void Dispose()
		{
			Client.Dispose();
		}
	}
}
