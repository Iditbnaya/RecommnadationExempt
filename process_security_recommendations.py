import pandas as pd
import requests
import json
from azure.identity import AzureCliCredential
from datetime import datetime, timezone
import csv
from azure.mgmt.subscription import SubscriptionClient

def get_all_subscriptions():
    """Get all accessible subscriptions"""
    credential = AzureCliCredential()
    subscription_client = SubscriptionClient(credential)
    subscriptions = []
    
    for sub in subscription_client.subscriptions.list():
        subscriptions.append({
            "id": sub.subscription_id,
            "name": sub.display_name,
            "state": sub.state
        })
    
    return subscriptions

def get_security_recommendations(subscription_id):
    """Get security recommendations for a subscription using Resource Graph"""
    credential = AzureCliCredential()
    token = credential.get_token("https://management.azure.com/.default").token
    
    url = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    # Query to get security recommendations
    query = {
        "subscriptions": [subscription_id],
        "query": """securityresources
        | where type == 'microsoft.security/assessments'
        | extend resourceId = tostring(properties.resourceDetails.id)
        | extend resourceIdParts = split(resourceId, '/')
        | extend resourceGroup = case(
            isnotempty(properties.resourceDetails.source), properties.resourceDetails.source,
            array_length(resourceIdParts) >= 5, resourceIdParts[4],
            ''
        )
        | extend resourceName = case(
            array_length(resourceIdParts) >= 9, resourceIdParts[8],
            ''
        )
        | extend resourceType = case(
            isnotempty(properties.resourceDetails.Source), properties.resourceDetails.Source,
            isnotempty(properties.resourceDetails.sourceResourceType), properties.resourceDetails.sourceResourceType,
            array_length(resourceIdParts) >= 8, strcat(resourceIdParts[6], '/', resourceIdParts[7]),
            'unknown'
        )
        | where properties.status.code == 'Unhealthy'
        | extend severity = properties.metadata.severity
        | extend recommendationType = properties.metadata.assessmentType
        | extend category = properties.metadata.category
        | extend displayName = properties.displayName
        | extend description = properties.description
        | extend remediationSteps = properties.metadata.remediationDescription
        | extend impact = properties.metadata.impact
        | extend businessImpact = severity
        | project
            recommendationId = id,
            resourceGroup = resourceGroup,
            resourceName = resourceName,
            resourceType = resourceType,
            resourceId = resourceId,
            displayName = displayName,
            severity = severity,
            businessImpact = businessImpact,
            state = properties.status.code,
            subscriptionId = subscriptionId,
            category = category,
            impact = impact,
            description = description,
            remediation = remediationSteps,
            recommendationType = recommendationType
        """
    }
    
    response = requests.post(url, headers=headers, json=query)
    if response.status_code == 200:
        return response.json().get('data', [])
    else:
        print(f"Error getting recommendations for subscription {subscription_id}: {response.text}")
        return []

def read_exemption_list(csv_file):
    """Read the CSV file containing recommendations to exempt"""
    try:
        df = pd.read_csv(csv_file)
        # Convert column names to match the expected format
        df.columns = [col.strip() for col in df.columns]  # Remove any whitespace
        return df.to_dict('records')
    except Exception as e:
        print(f"Error reading CSV file: {str(e)}")
        return []

def create_exemption(subscription_id, resource_group, recommendation_id, resource_name, resource_type, display_name, business_impact=None, potential_benefits=None):
    """Create a policy exemption using the REST API"""
    credential = AzureCliCredential()
    token = credential.get_token("https://management.azure.com/.default").token
    
    # Create a unique but readable exemption name based on resource and date
    safe_resource_name = ''.join(c for c in resource_name if c.isalnum())[:30]
    exemption_name = f"exempt-{safe_resource_name}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    
    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}/resourcegroups/{resource_group}/"
        f"providers/Microsoft.Authorization/policyExemptions/{exemption_name}?api-version=2022-07-01-preview"
    )
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    body = {
        "properties": {
            "policyAssignmentId": f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/policyAssignments/SecurityCenterBuiltIn",
            "policyDefinitionReferenceIds": [recommendation_id],
            "exemptionCategory": "Waiver",
            "displayName": f"Automated Exemption - {display_name}",
            "description": f"Automated exemption created for {resource_name} in {resource_group}",
            "expiresOn": "2025-12-31T23:59:59Z",
            "metadata": {
                "requestedBy": "Automation Script",
                "approvedBy": "Security Team",
                "justification": potential_benefits or "Automated exemption based on approved list",
                "businessImpact": business_impact or "Not specified",
                "resourceGroup": resource_group,
                "resourceName": resource_name,
                "resourceType": resource_type,
                "recommendationId": recommendation_id,
                "createdOn": datetime.now(timezone.utc).isoformat()
            }
        }
    }
    
    try:
        response = requests.put(url, headers=headers, json=body)
        response.raise_for_status()
        return True, response.json()
    except Exception as e:
        return False, str(e)

def main():
    # File paths
    input_csv = "recommendations_to_exempt.csv"  # CSV with recommendations to exempt
    output_csv = "processed_recommendations.csv"  # CSV with processed recommendations
    
    # Get all subscriptions
    print("Getting all subscriptions...")
    subscriptions = get_all_subscriptions()
    
    # Get all recommendations from all subscriptions
    all_recommendations = []
    for sub in subscriptions:
        print(f"Getting recommendations for subscription: {sub['name']}")
        recommendations = get_security_recommendations(sub['id'])
        all_recommendations.extend(recommendations)
    
    # Read the list of recommendations to exempt
    print("Reading exemption list from CSV...")
    exemption_list = read_exemption_list(input_csv)
    
    # Compare and create list of recommendations to process
    recommendations_to_process = []
    print(f"\nFound {len(all_recommendations)} total recommendations")
    print(f"Found {len(exemption_list)} recommendations in exemption list")
    
    # Debug: Print sample recommendations
    print("\nSample recommendations from Azure:")
    for i, rec in enumerate(all_recommendations[:3]):
        print(f"\nRecommendation {i + 1}:")
        print(f"  Display Name: {rec.get('displayName', '')}")
        print(f"  Severity: {rec.get('severity', '')}")
        print(f"  Resource Group: {rec.get('resourceGroup', '')}")
        print(f"  Resource Name: {rec.get('resourceName', '')}")
        print(f"  Resource Type: {rec.get('resourceType', '')}")
        print(f"  Subscription ID: {rec.get('subscriptionId', '')}")
    
    # Debug: Print sample exemption requests
    print("\nSample exemption requests from CSV:")
    for i, exempt in enumerate(exemption_list[:3]):
        print(f"\nExemption Request {i + 1}:")
        for key, value in exempt.items():
            print(f"  {key}: {value}")
    
    for rec in all_recommendations:
        for exempt_rec in exemption_list:
            try:
                # Clean and normalize strings for comparison
                rec_name = rec.get('displayName', '').lower().strip()
                exempt_name = exempt_rec.get('Recommendation', '').lower().strip()
                rec_severity = rec.get('severity', '').lower().strip()
                exempt_severity = exempt_rec.get('Business Impact', '').lower().strip()
                
                # Get resource details
                rec_sub_id = rec.get('subscriptionId', '').lower().strip()
                exempt_sub_id = exempt_rec.get('Subscription ID', '').lower().strip()
                rec_rg = rec.get('resourceGroup', '').lower().strip()
                exempt_rg = exempt_rec.get('Resource Group', '').lower().strip()
                rec_resource = rec.get('resourceName', '').lower().strip()
                exempt_resource = exempt_rec.get('Resource Name', '').lower().strip()
                rec_type = rec.get('resourceType', '').lower().strip()
                exempt_type = exempt_rec.get('Type', '').lower().strip()

                # Handle potential variations in recommendation names
                rec_name_normalized = rec_name.replace('[preview]', '').strip()
                exempt_name_normalized = exempt_name.replace('[preview]', '').strip()
                
                # Normalize resource types
                rec_type_normalized = rec_type.split('/')[-1] if '/' in rec_type else rec_type
                exempt_type_normalized = exempt_type.split('/')[-1] if '/' in exempt_type else exempt_type
                
                # Check if recommendation matches the exemption criteria
                # More flexible recommendation name matching with detailed debug
                recommendation_matches = False
                rec_words = set(word.lower() for word in rec_name_normalized.split() if len(word) > 2)  # Ignore small words
                exempt_words = set(word.lower() for word in exempt_name_normalized.split() if len(word) > 2)
                word_overlap = len(rec_words.intersection(exempt_words))
                words_in_common = rec_words.intersection(exempt_words)
                
                print(f"\nComparing recommendation:")
                print(f"Azure: {rec_name_normalized}")
                print(f"CSV:   {exempt_name_normalized}")
                print(f"Words in common: {words_in_common}")
                
                # Match if at least one significant word overlaps
                if word_overlap >= 1:
                    recommendation_matches = True
                    print("MATCH: At least one significant word overlaps")
                elif rec_name_normalized in exempt_name_normalized:
                    recommendation_matches = True
                    print("MATCH: Azure recommendation name is contained in CSV name")
                elif exempt_name_normalized in rec_name_normalized:
                    recommendation_matches = True
                    print("MATCH: CSV recommendation name is contained in Azure name")
                else:
                    print("NO MATCH: Recommendation names do not match")

                # More flexible severity matching
                severity_matches = True
                if exempt_severity:
                    severity_matches = (
                        rec_severity.lower() == exempt_severity.lower() or
                        (rec_severity.lower() in ['high', 'critical'] and exempt_severity.lower() in ['high', 'critical']) or
                        (rec_severity.lower() in ['medium', 'moderate'] and exempt_severity.lower() in ['medium', 'moderate']) or
                        (rec_severity.lower() in ['low', 'minor'] and exempt_severity.lower() in ['low', 'minor'])
                    )
                    print(f"Comparing severity: Azure={rec_severity}, CSV={exempt_severity}, Match={severity_matches}")
                else:
                    print("No severity specified in CSV, accepting any severity")

                # Resource matching with debug output
                subscription_matches = not exempt_sub_id or rec_sub_id == exempt_sub_id
                rg_matches = not exempt_rg or rec_rg == exempt_rg
                resource_matches = not exempt_resource or rec_resource == exempt_resource
                
                print(f"Resource matching:")
                print(f"  Subscription: Azure={rec_sub_id}, CSV={exempt_sub_id}, Match={subscription_matches}")
                print(f"  Resource Group: Azure={rec_rg}, CSV={exempt_rg}, Match={rg_matches}")
                print(f"  Resource Name: Azure={rec_resource}, CSV={exempt_resource}, Match={resource_matches}")
                
                resource_matches = subscription_matches and rg_matches and resource_matches

                # More flexible type matching
                type_matches = True
                if exempt_type:
                    type_matches = (
                        rec_type_normalized == exempt_type_normalized or
                        rec_type_normalized in exempt_type_normalized or
                        exempt_type_normalized in rec_type_normalized or
                        any(word in rec_type_normalized for word in exempt_type_normalized.split()) or
                        any(word in exempt_type_normalized for word in rec_type_normalized.split())
                    )
                    print(f"Comparing type: Azure={rec_type_normalized}, CSV={exempt_type_normalized}, Match={type_matches}")
                else:
                    print("No resource type specified in CSV, accepting any type")

                if recommendation_matches and severity_matches and resource_matches and type_matches:
                    # Add debug output to understand why it matched
                    print(f"\nMatched recommendation with criteria:")
                    print(f"  Azure Name: {rec_name_normalized}")
                    print(f"  CSV Name: {exempt_name_normalized}")
                    print(f"  Azure Severity: {rec_severity}")
                    print(f"  CSV Severity: {exempt_severity}")
                    print(f"  Azure Type: {rec_type_normalized}")
                    print(f"  CSV Type: {exempt_type_normalized}")
                    print(f"  Word overlap: {word_overlap} words")
                    
                    print(f"\nMatched recommendation:")
                    print(f"  Name: {rec.get('displayName')}")
                    print(f"  Severity: {rec.get('severity')}")
                    print(f"  Resource: {rec.get('resourceName')}")
                    print(f"  Type: {rec.get('resourceType')}")
                    
                    recommendations_to_process.append({
                        'subscriptionId': rec.get('subscriptionId', ''),
                        'resourceGroup': rec.get('resourceGroup', ''),
                        'resourceName': rec.get('resourceName', ''),
                        'resourceType': rec.get('resourceType', ''),
                        'recommendationId': rec.get('recommendationId', ''),
                        'displayName': rec.get('displayName', ''),
                        'severity': rec.get('severity', ''),
                        'category': rec.get('category', ''),
                        'impact': rec.get('impact', ''),
                        'description': rec.get('description', ''),
                        'remediation': rec.get('remediation', ''),
                        'status': 'Pending'
                    })
            except Exception as e:
                print(f"Error processing recommendation: {str(e)}")
                continue
    
    print(f"\nFound {len(recommendations_to_process)} recommendations to process")
    
    # Save to CSV
    if recommendations_to_process:
        print(f"Saving {len(recommendations_to_process)} recommendations to process...")
        with open(output_csv, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=recommendations_to_process[0].keys())
            writer.writeheader()
            writer.writerows(recommendations_to_process)
    
    # Create exemptions
    print("Creating exemptions...")
    for rec in recommendations_to_process:
        print(f"Processing: {rec['displayName']} for {rec['resourceName']}")
        success, result = create_exemption(
            rec['subscriptionId'],
            rec['resourceGroup'],
            rec['recommendationId'],
            rec['resourceName'],
            rec['resourceType'],
            rec['displayName'],
            rec.get('Business Impact'),
            rec.get('Potential benefits')
        )
        
        if success:
            print(f"Successfully created exemption for {rec['resourceName']}")
            rec['status'] = 'Exempted'
        else:
            print(f"Failed to create exemption for {rec['resourceName']}: {result}")
            rec['status'] = f'Failed: {result}'
    
    # Update CSV with results
    print("Updating CSV with results...")
    fieldnames = ['subscriptionId', 'resourceGroup', 'resourceName', 'resourceType', 
                 'recommendationId', 'displayName', 'severity', 'status']
    with open(output_csv, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        if recommendations_to_process:
            writer.writerows(recommendations_to_process)
            print(f"Created {output_csv} with {len(recommendations_to_process)} recommendations")
        else:
            print("No recommendations found to process")
    
    print("Process completed!")

if __name__ == "__main__":
    main()
