import boto3
from botocore.exceptions import ClientError

def cloudtrail_insights_exist():
    """
    Check if CloudTrail Insights are enabled for anomaly detection.
    
    Returns:
        dict: Compliance check result with status and details
    """
    try:
        # Create CloudTrail client
        cloudtrail_client = boto3.client('cloudtrail')
        
        # Get all trails
        response = cloudtrail_client.describe_trails()
        trails = response.get('trailList', [])
        
        if not trails:
            return {
                'status': 'FAIL',
                'message': 'No CloudTrail trails found',
                'resource_id': 'N/A',
                'details': 'CloudTrail should be configured with Insights for anomaly detection'
            }
        
        trails_with_insights = []
        trails_without_insights = []
        
        for trail in trails:
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN', trail_name)
            
            try:
                # Get insight selectors for the trail
                insight_response = cloudtrail_client.get_insight_selectors(TrailName=trail_arn)
                insight_selectors = insight_response.get('InsightSelectors', [])
                
                # Check if any insights are enabled
                has_insights = False
                insight_types = []
                
                for selector in insight_selectors:
                    insight_type = selector.get('InsightType')
                    if insight_type:
                        has_insights = True
                        insight_types.append(insight_type)
                
                if has_insights:
                    trails_with_insights.append(f"{trail_name} ({', '.join(insight_types)})")
                else:
                    trails_without_insights.append(trail_name)
                    
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                if error_code == 'TrailNotFoundException':
                    trails_without_insights.append(f"{trail_name} (not found)")
                elif error_code == 'InsightNotEnabledException':
                    trails_without_insights.append(f"{trail_name} (insights not enabled)")
                else:
                    trails_without_insights.append(f"{trail_name} (error: {error_code})")
        
        if trails_without_insights:
            return {
                'status': 'FAIL',
                'message': f'CloudTrail trails without Insights: {", ".join(trails_without_insights)}',
                'resource_id': trails_without_insights[0].split(' ')[0],
                'details': f'{len(trails_without_insights)} trail(s) missing CloudTrail Insights for anomaly detection'
            }
        else:
            return {
                'status': 'PASS',
                'message': f'All CloudTrail trails have Insights enabled: {", ".join(trails_with_insights)}',
                'resource_id': trails_with_insights[0].split(' ')[0] if trails_with_insights else 'N/A',
                'details': f'Found {len(trails_with_insights)} trail(s) with CloudTrail Insights'
            }
    
    except ClientError as e:
        return {
            'status': 'ERROR',
            'message': f'Error checking CloudTrail Insights: {str(e)}',
            'resource_id': 'N/A',
            'details': str(e)
        }
    except Exception as e:
        return {
            'status': 'ERROR',
            'message': f'Unexpected error: {str(e)}',
            'resource_id': 'N/A',
            'details': str(e)
        }

if __name__ == "__main__":
    result = cloudtrail_insights_exist()
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Resource ID: {result['resource_id']}")
    print(f"Details: {result['details']}")