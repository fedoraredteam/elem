import unittest
from elem import ConfigurationHandler
from elem import DEFAULT_CONFIG_FILE

class TestConfigFile(unittest.TestCase):
    def setUp(self):
        self.config_handler = ConfigurationHandler()

    def test_default(self):
        self.assertEqual(self.config_handler.config_file, DEFAULT_CONFIG_FILE)
        
    def test_get_config(self):
        config = self.config_handler.read_config()
        self.assertIsNotNone(config)
        self.assertTrue(config.get('cpe','url'), 'http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz')
        self.assertTrue(config.get('cpe','location'), './data/cpe')

if __name__ == '__main__':
    unittest.main()