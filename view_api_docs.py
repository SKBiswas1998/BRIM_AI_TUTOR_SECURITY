import requests
import json

print("="*60)
print("EXTRACTING COMPLETE API DOCUMENTATION")
print("="*60)

# Get the OpenAPI schema
url = "https://fastapi-tutor-app-backend-208251878692.asia-south1.run.app/openapi.json"
response = requests.get(url)

if response.status_code == 200:
    api_doc = response.json()
    
    # Save full documentation
    with open("brimai_api_documentation.json", "w") as f:
        json.dump(api_doc, f, indent=2)
    print("✓ Full API documentation saved to: brimai_api_documentation.json")
    
    # Display API info
    print(f"\nAPI Title: {api_doc.get('info', {}).get('title')}")
    print(f"Version: {api_doc.get('info', {}).get('version')}")
    print(f"Description: {api_doc.get('info', {}).get('description', 'N/A')}")
    
    # Display all endpoints with details
    print("\n" + "="*60)
    print("COMPLETE ENDPOINT DOCUMENTATION")
    print("="*60)
    
    paths = api_doc.get('paths', {})
    for path, methods in paths.items():
        for method, details in methods.items():
            print(f"\n{method.upper()} {path}")
            print("-" * 40)
            
            # Summary
            if 'summary' in details:
                print(f"Summary: {details['summary']}")
            
            # Description
            if 'description' in details:
                print(f"Description: {details['description']}")
            
            # Parameters
            if 'parameters' in details:
                print("\nParameters:")
                for param in details['parameters']:
                    required = "Required" if param.get('required', False) else "Optional"
                    print(f"  - {param['name']} ({param['in']}) [{required}]")
                    if 'description' in param:
                        print(f"    {param['description']}")
            
            # Request body
            if 'requestBody' in details:
                print("\nRequest Body:")
                content = details['requestBody'].get('content', {})
                for content_type, schema_info in content.items():
                    print(f"  Content-Type: {content_type}")
                    if 'schema' in schema_info and '$ref' in schema_info['schema']:
                        schema_name = schema_info['schema']['$ref'].split('/')[-1]
                        print(f"  Schema: {schema_name}")
            
            # Responses
            if 'responses' in details:
                print("\nResponses:")
                for status_code, response_info in details['responses'].items():
                    print(f"  {status_code}: {response_info.get('description', '')}")
    
    # Display data models
    print("\n" + "="*60)
    print("DATA MODELS/SCHEMAS")
    print("="*60)
    
    schemas = api_doc.get('components', {}).get('schemas', {})
    for schema_name, schema_def in schemas.items():
        print(f"\n{schema_name}:")
        print("-" * 40)
        
        # Properties
        if 'properties' in schema_def:
            print("Properties:")
            for prop_name, prop_def in schema_def['properties'].items():
                prop_type = prop_def.get('type', 'unknown')
                required = prop_name in schema_def.get('required', [])
                req_str = " (required)" if required else ""
                print(f"  - {prop_name}: {prop_type}{req_str}")
                
                # Show additional details
                if 'description' in prop_def:
                    print(f"    {prop_def['description']}")
                if 'example' in prop_def:
                    print(f"    Example: {prop_def['example']}")
        
        # Required fields
        if 'required' in schema_def:
            print(f"Required fields: {', '.join(schema_def['required'])}")

    # Security schemes
    print("\n" + "="*60)
    print("SECURITY CONFIGURATION")
    print("="*60)
    
    security_schemes = api_doc.get('components', {}).get('securitySchemes', {})
    if security_schemes:
        for scheme_name, scheme_def in security_schemes.items():
            print(f"\n{scheme_name}:")
            print(f"  Type: {scheme_def.get('type')}")
            print(f"  Scheme: {scheme_def.get('scheme', 'N/A')}")
    else:
        print("❌ NO SECURITY SCHEMES DEFINED!")
    
    # Global security
    global_security = api_doc.get('security', [])
    if global_security:
        print(f"\nGlobal Security: {global_security}")
    else:
        print("\n❌ NO GLOBAL SECURITY APPLIED!")

else:
    print(f"Failed to get API documentation: {response.status_code}")

print("\n" + "="*60)
print("SECURITY ANALYSIS")
print("="*60)

print("\n🔍 What attackers learn from this:")
print("1. All available endpoints and their exact paths")
print("2. Required parameters for each endpoint")
print("3. Expected request/response formats")
print("4. Data models and their structures")
print("5. Which endpoints lack authentication")
print("6. How to craft valid requests")
print("\n❌ This is a goldmine for attackers!")
