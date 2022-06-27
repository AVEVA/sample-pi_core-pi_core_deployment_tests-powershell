namespace OSIsoft.PISystemDeploymentTests
{
    using System;
    using System.Configuration;
    using System.IO;

    /// <summary>
    /// Class to manange getting config values from the runtime settings
    /// </summary>
    internal class SettingsManager
    {
        /// <summary>
        /// The instance
        /// </summary>
        private static readonly SettingsManager _instance = new SettingsManager();

        /// <summary>
        /// The path to find the run.config file
        /// </summary>
        private static string _modulePath;

        /// <summary>
        /// The collection of configuration settings
        /// </summary>
        private KeyValueConfigurationCollection _runConfigSettings;

        /// <summary>
        /// Constructor for the settings manager.  It calls InitSettingsFile to load the runtine
        /// config file from the temp folder
        /// </summary>
        public SettingsManager()
        {
            InitSettingsFile();
        }

        /// <summary>
        /// Singleton accessor
        /// </summary>
        public static SettingsManager Instance
        {
            get
            {
                return _instance;
            }
        }

        /// <summary>
        /// Gets the string value from the AppSettings section of the Run.config file.
        /// </summary>
        /// <param name="settingName">Name of the setting.</param>
        /// <param name="isRequired">If true, the setting to be used is required (default false).</param>
        /// <returns>The setting value for the specified name.</returns>
        /// <exception cref="ArgumentNullException">
        /// This exception if thrown if the isRequired parameter is true and the setting value is not specified.
        /// </exception>
        public string GetValue(string settingName, bool isRequired = false)
        {
            string settingValue = string.Empty;
            KeyValueConfigurationElement element = _runConfigSettings[settingName];
            settingValue = element == null ? string.Empty : element.Value;

            if (isRequired && string.IsNullOrWhiteSpace(settingValue))
                throw new ArgumentNullException($"The setting '{settingName}' is missing in App.config at :: {_modulePath}.");

            return settingValue;
        }

        /// <summary>
        /// Load the settings from the run.config file in the user temp folder
        /// </summary>
        private void InitSettingsFile()
        {
            string userTempFolder = Path.GetTempPath();
            _modulePath = userTempFolder;

            if (!string.IsNullOrEmpty(userTempFolder)) 
            {
                string modulePath = Path.GetDirectoryName(userTempFolder);

                ExeConfigurationFileMap runConfigMap = new ExeConfigurationFileMap();
                runConfigMap.ExeConfigFilename = modulePath + @"\run.config";
                Configuration runConfig = ConfigurationManager.OpenMappedExeConfiguration(runConfigMap, ConfigurationUserLevel.None);

                if (runConfig != null)
                {
                    _runConfigSettings = runConfig.AppSettings.Settings;
                }
            }
        }
    }
}
