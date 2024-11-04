import asyncio
from datetime import datetime
from decimal import Decimal
import aiohttp
import os
import json
from bs4 import BeautifulSoup
from langchain_openai import ChatOpenAI

from get_cve import get_filtered_cves

def default_serializer(obj):
    """ Custom serializer to handle non-serializable objects like datetime and Decimal """
    if isinstance(obj, datetime):
        return obj.isoformat()  # Convert datetime to ISO format
    elif isinstance(obj, Decimal):
        return float(obj)  # Convert Decimal to float for JSON serialization
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

def extract_advisory_links(cve):
    advisory_links = []
    references_field = cve.get('references', '[]')  # Get the 'references' field, default to empty list string
    try:
        # Parse the 'references' field as JSON
        references = json.loads(references_field)
        # Extract URLs from the references
        for ref in references:
            url = ref.get('url')
            if url:
                advisory_links.append(url)
    except json.JSONDecodeError as e:
        print(f"Error parsing references for CVE ID {cve['cve_id']}: {e}")
    return advisory_links

async def scrape_urls(urls):
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_url(session, url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results

async def fetch_url(session, url):
    try:
        async with session.get(url, timeout=15) as response:
            if response.status == 200:
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                text_content = soup.get_text(separator='\n', strip=True)
                return {'url': url, 'content': text_content}
            else:
                return {'url': url, 'content': f'Failed to fetch: {response.status}'}
    except Exception as e:
        return {'url': url, 'content': str(e)}

def create_prompt_for_patch_and_mitigation(cve):
    prompt = f"""
You are a knowledgeable, efficient, and direct AI assistant specializing in cybersecurity, system vulnerabilities, and risk assessment. Provide concise answers in JSON format, focusing on the key information needed. Analyze the provided scraped data  from the corresponding advisory URL for the given CVE :

**CVE Details:**
"""
    # Iterate over all key-value pairs in the cve dictionary
    for key, value in cve.items():
        if key != 'advisory_contents':  # Exclude advisory_contents to avoid duplication
            # Format the key to have spaces and capitalize words (e.g., 'cve_id' -> 'CVE ID')
            formatted_key = ' '.join(word.capitalize() for word in key.split('_'))
            # Handle values that are dictionaries or lists
            if isinstance(value, (dict, list)):
                value_str = json.dumps(value, indent=2)
                prompt += f"- **{formatted_key}:**\n```\n{value_str}\n```\n"
            else:
                prompt += f"- **{formatted_key}:** {value}\n"

    prompt += """
    **Advisory Contents:**
    """
    # Include advisory contents if available
    for advisory in cve.get('advisory_contents', []):
        prompt += f"\n- **URL:** {advisory['url']}\n**Content:**\n{advisory['content']}\n"

    prompt += f"""
**Instructions:**

to determine::
1. If a patch is available for the CVE:
   - Identify mentions of a valid patch, fix, update version, solution, or fixed version addressing CVE ID {cve['cve_id']}.
   - Exclude URLs with placeholders like "example.com" or variations containing the word "example".
   - Verify that the identified patch URL specifically targets the vulnerability associated with CVE ID {cve['cve_id']}.
   - Ensure the patch release link is accessible, functional, and not null. Confirm that the URL is live and reachable.
   - The URL must match exactly as found in the scraped data without truncation, modification, or incorrect formatting.
   - Verify the URL points directly to a patch or fix for the CVE and not to general information or unrelated content.

2. If no patch is available, provide recommended mitigations:
   - Identify comprehensive and specific mitigation measures for CVE ID {cve['cve_id']}.
   - Offer clear, actionable steps to protect systems from the vulnerability.
   - Include specific control measures tailored to the identified vulnerability based on the scraped data. Avoid generic responses.
   - Include details on:
     - Technical adjustments or configurations needed.
     - Steps for immediate containment and isolation.
     - Actions for enhanced monitoring and automated responses.
     - Long-term risk management and security policy improvements.
   - Address potential attack vectors: Identify and address possible attack vectors and potential consequences associated with the vulnerability, ensuring comprehensive coverage of all known exploit paths.
   - Recommend alternative solutions: Offer detailed recommendations for alternative solutions or temporary workarounds based on available data, ensuring users have practical options to mitigate risks in the absence of a patch.
   - Identify additional security best practices to enhance overall security posture. Focus on actions, configurations, or network adjustments based on the scraped data insights.

Include a reasoning step to verify the accuracy of your response:
- After generating the initial response, re-evaluate the patch URL and mitigation measures to ensure they are correct and directly related to the CVE .
- Verify that the patch URL is complete and exactly matches the one found in the scraped data without any truncation or modification. If the patch URL is incorrect, correct it.
- If any part of the response is incorrect, correct it and provide the accurate information.

Response Format:

You reply in JSON format with the fields 'patch_available', 'patch' and 'mitigation_measures' .

Example response when a patch is available:
{{
  "patch_available": true,
  "patch": {{
    "release_link": "https://valid.patch.url",
    "last_update": "2023-12-01",
    "recommendations": "Apply this patch to address the vulnerability."
  }},
  "mitigation_measures": null
}}

Example response when a patch is not available:
{{
  "patch_available": false,
  "patch": null,
  "mitigation_measures": "Implement input validation and use a Web Application Firewall. Regularly audit your systems and monitor for suspicious activity."
}}

Respond only in JSON format; I don't need any other comments or text.
Conditions:
- Only provide patch OR mitigation, not both.
- Ensure valid JSON format without extraneous characters. Respond only in JSON format.
- Provide sources or evidence for any claims.
- Verify that patch URLs are complete, accurate, and exactly as found in the scraped data without any modifications. Ensure they point directly to the patch or fix.
- Include a reasoning step to verify the accuracy of your response. """

    return prompt

async def process_cve_patch_and_mitigation(cve):
    print(f"Processing CVE ID: {cve['cve_id']}")
    # Extract advisory links
    references = extract_advisory_links(cve)
    # Limit to 3 references if there are more
    if len(references) > 3:
        references = references[:3]
    # Scrape the advisory contents
    try:
        cve['advisory_contents'] = await scrape_urls(references)
    except Exception as e:
        print(f"Error during advisory scraping: {e}")
        cve['advisory_contents'] = []
    # Create the prompt
    prompt = create_prompt_for_patch_and_mitigation(cve)
    if not prompt:
        return None  # Skip if no prompt (e.g., missing data)
    
    # Call the LLM
    try:
        # Initialize the LLM
        llm = ChatOpenAI(
            model_name='gpt-4o-mini',
            temperature=0.0,
        )
        
        # Get the response from the LLM
        response = llm.invoke(prompt)
        output_text = response.content.strip()
        
        # Clean the output_text by removing code block delimiters and language specifiers
        output_text = output_text.strip()
        if output_text.startswith('```'):
            output_text = output_text.strip('`')
            # Remove the language specifier if present
            if output_text.startswith('json'):
                output_text = output_text[4:].strip()
        
        # Parse the JSON output
        try:
            result = json.loads(output_text)
            # Update the CVE with new attributes
            cve['patch_available'] = result.get('patch_available')
            cve['patch'] = result.get('patch')
            cve['mitigation_measures'] = result.get('mitigation_measures')
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON response for CVE ID {cve['cve_id']}: {e}")
            print("LLM Output:")
            print(output_text)
            return None  # Skip further processing if parsing fails
        cve['advisory_contents'] = ' '
        return cve  # Return the augmented CVE
    
    except Exception as e:
        print(f"Error during LLM processing for CVE ID {cve['cve_id']}: {e}")
        return None

""" async def main():
    cves_with_recommendations = []
    cves = get_filtered_cves(2023, 2023, max_cves=20)  # Adjust the parameters as needed
    
    # Optionally, skip the first n CVEs
    n = 10  # Number of CVEs to skip
    cves = cves[n:]
    
    for cve in cves:
        augmented_cve = await process_cve_patch_and_mitigation(cve)
        if augmented_cve:
            cves_with_recommendations.append(augmented_cve)
    
    # Optionally, save the augmented CVEs to a file or database
    with open('cves_with_recommendations_2023_1.json', 'w') as f:
        json.dump(cves_with_recommendations, f, indent=2, default=default_serializer)
    
    print("Completed processing CVEs for patch availability and mitigation measures.")

 """