#!/usr/bin/env python3
"""
Configuration-Based AWS Scanner Test

Tests the configuration manager and multi-client scanning approach.
"""

import sys
import os
import json
import logging
from datetime import datetime

# Add current directory to path
sys.path.insert(0, os.getcwd())

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Test configuration-based scanning"""
    print("🔍 Configuration-Based AWS Scanner Test")
    print("=" * 60)
    print("🏗️ Testing configuration manager")
    print("🎯 Multi-client credential support")
    print("=" * 60)
    
    try:
        # Import configuration manager
        from utils.secret_manager import get_secret_manager
        
        # Initialize configuration manager
        print("\n🚀 Initializing Configuration Manager...")
        secret_manager = get_secret_manager()
        
        # Validate configuration
        print("🔍 Validating Configuration...")
        if not secret_manager.validate_configuration():
            print("❌ Configuration validation failed")
            print("💡 Please check your config/aws_credentials_config.json file")
            return 1
        
        print("✅ Configuration validation passed")
        
        # Display available profiles
        profiles = secret_manager.get_all_profiles()
        print(f"\n📋 Available AWS Profiles ({len(profiles)}):")
        for profile in profiles:
            print(f"  • {profile.name} ({profile.type})")
            print(f"    - Region: {profile.region}")
            print(f"    - Account: {profile.account_name or 'Unknown'}")
            if profile.account_id:
                print(f"    - Account ID: {profile.account_id}")
        
        # Test session creation for each profile
        print(f"\n🔧 Testing Session Creation:")
        for profile in profiles:
            print(f"\n  Testing Profile: {profile.name}")
            
            session = secret_manager.create_boto3_session(profile.name)
            if session:
                try:
                    # Test the session
                    sts_client = session.client('sts')
                    identity = sts_client.get_caller_identity()
                    print(f"    ✅ Connected: {identity['Account']}")
                    print(f"    ✅ User: {identity['Arn']}")
                except Exception as e:
                    print(f"    ❌ Connection failed: {str(e)[:50]}...")
            else:
                print(f"    ❌ Session creation failed")
        
        # Test output filename generation
        print(f"\n📁 Testing Output Configuration:")
        for profile in profiles:
            filename = secret_manager.get_output_filename(profile.name)
            print(f"  • {profile.name}: {filename}")
        
        # Show scan configuration
        scan_config = secret_manager.scan_config
        print(f"\n🔧 Scan Configuration:")
        print(f"  • Default Regions: {', '.join(scan_config.default_regions)}")
        print(f"  • Services to Scan: {', '.join(scan_config.services_to_scan)}")
        print(f"  • Max Workers: {scan_config.max_workers}")
        print(f"  • Timeout: {scan_config.scan_timeout_seconds}s")
        
        # Show output configuration
        output_config = secret_manager.output_config
        print(f"\n📁 Output Configuration:")
        print(f"  • Directory: {output_config.output_directory}")
        print(f"  • Prefix: {output_config.filename_prefix}")
        print(f"  • Include Timestamp: {output_config.include_timestamp}")
        print(f"  • Format: {output_config.format}")
        
        # Test secret management
        print(f"\n🔐 Secret Management:")
        secrets = secret_manager.secrets
        if secrets:
            print(f"  ✅ Secrets loaded successfully")
            aws_creds = secrets.get('aws_credentials', {})
            print(f"  • AWS Credentials: {len(aws_creds)} profiles")
            for profile_name in aws_creds.keys():
                print(f"    - {profile_name}")
        else:
            print(f"  ⚠️  No secrets loaded")
        
        # Create sample output
        print(f"\n💾 Creating Sample Output...")
        sample_results = {
            'scan_id': 'config_test_scan',
            'scan_timestamp': datetime.now().isoformat(),
            'configuration_test': True,
            'profiles_tested': len(profiles),
            'sample_finding': {
                'check_name': 'configuration_test',
                'status': 'PASS',
                'status_extended': 'Configuration manager working correctly',
                'account_name': 'test',
                'region': 'us-east-1',
                'service': 'config'
            }
        }
        
        # Save sample output
        output_file = secret_manager.get_output_filename('test')
        os.makedirs('output', exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(sample_results, f, indent=2, default=str)
        
        print(f"✅ Sample output saved to: {output_file}")
        
        # Show file content
        print(f"\n📄 Sample Output Content:")
        print("-" * 50)
        with open(output_file, 'r') as f:
            print(f.read())
        
        print(f"\n🎯 Configuration-based scanning system is ready!")
        print(f"📋 Next steps:")
        print(f"  1. Update config/aws_credentials_config.json with your client profiles")
        print(f"  2. Create config/secrets.json with actual credentials")
        print(f"  3. Run the multi-client scanner")
        
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        print("Make sure all required modules are available")
        return 1
    except Exception as e:
        print(f"❌ Error: {e}")
        logger.error(f"Configuration test failed: {e}", exc_info=True)
        return 1
    
    print(f"\n🎉 Configuration test completed successfully!")
    return 0

if __name__ == "__main__":
    sys.exit(main()) 