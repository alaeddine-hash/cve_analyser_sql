import asyncio
from datetime import datetime
from decimal import Decimal
import aiohttp
import os
import json
from bs4 import BeautifulSoup
from langchain_openai import ChatOpenAI

from get_cve import get_filtered_cves
import logging

# Configure logging to write to a file
logging.basicConfig(
    filename='cve_processing.log',  # Log file name
    level=logging.INFO,             # Log level
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='w'                    # 'w' to overwrite the log file each run
)

# Replace all print statements with logging
def log_info(message):
    logging.info(message)
    print(message)  # Optional: still print to console if needed


def default_serializer(obj):
    """ Custom serializer to handle non-serializable objects like datetime and Decimal """
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, Decimal):
        return float(obj)
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

def extract_advisory_links(cve):
    advisory_links = []
    references_field = cve.get('references', '[]')
    try:
        references = json.loads(references_field)
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

def create_prompt_for_cve_augmentation(cve):
    prompt = f"""
You are a cybersecurity analyst with expertise in vulnerability assessment. Your task is to analyze the following CVE details and advisory contents to extract specific information.

**CVE Details:**
"""
    for key, value in cve.items():
        if key != 'advisory_contents':
            formatted_key = ' '.join(word.capitalize() for word in key.split('_'))
            if isinstance(value, (dict, list)):
                value_str = json.dumps(value, indent=2)
                prompt += f"- **{formatted_key}:**\n```\n{value_str}\n```\n"
            else:
                prompt += f"- **{formatted_key}:** {value}\n"

    prompt += """
**Advisory Contents:**
"""
    for advisory in cve.get('advisory_contents', []):
        prompt += f"\n- **URL:** {advisory['url']}\n**Content:**\n{advisory['content']}\n"

    prompt += """
**Instructions:**

From the provided information, extract the following attributes:


1. **Vulnerability-Component-Name:**
   - Name of the vulnerable component (e.g., "OpenSSL", "Apache").
   - If not specified, return `null`.

2. **Vulnerability-Component-Version:**
   - Version of the vulnerable component.
   - If not specified, return `null`.

3. **Vulnerability-Component-Type:**
   - Specify the component type. Choose from the following options: `webapp`, `library`, `database`, `kernel`, `driver`, or `app`.
   - If not specified, return `null`.

4. Ensure that the number of items in `Vulnerability-Component-Name` and `Vulnerability-Component-Version` match correctly, even if the version ranges cover multiple entries.

**Output Format:**

Provide your response in valid JSON format with the following structure:

```json
{

  "vulnerability_component_name": "Component Name" or null,
  "vulnerability_component_version": "Component Version" or null,
  "vulnerability_component_type": "Component Type" or null
}

Important Guidelines:

Do not include any explanations, introductions, or conclusions.

Provide only the JSON object.

Do not include any code block delimiters or language specifiers.

Ensure the JSON is properly formatted and parsable. """

    return prompt

async def process_cve_augmentation_component(cve):
    print(f"Processing CVE ID: {cve['cve_id']}")
    references = extract_advisory_links(cve)
    if len(references) > 3:
        references = references[:3]

    # Scrape the advisory contents
    try:
        cve['advisory_contents'] = await scrape_urls(references)
    except Exception as e:
        print(f"Error during advisory scraping: {e}")
        cve['advisory_contents'] = []

    # Create the prompt
    prompt = create_prompt_for_cve_augmentation(cve)

    # Call the LLM
    try:
        # Initialize the LLM
        llm = ChatOpenAI(
            model_name='gpt-4o-mini',  # Or 'gpt-3.5-turbo'
            temperature=0.0,
        )

        # Get the response from the LLM
        response = llm.invoke(prompt)
        output_text = response.content.strip()

        # Clean the output_text by removing code block delimiters and language specifiers
        output_text = output_text.strip()
        if output_text.startswith('```'):
            output_text = output_text.strip('`')
            if output_text.startswith('json'):
                output_text = output_text[4:].strip()

        # Parse the JSON output
        try:
            result = json.loads(output_text)
            #print(f"LLM Output: {result}")
            vulnerability_component_name = result.get('vulnerability_component_name')
            vulnerability_component_version = result.get('vulnerability_component_version')
            vulnerability_component_type = result.get('vulnerability_component_type')

            cve['advisory_contents'] = ' '
            if isinstance(vulnerability_component_name, list):
                vulnerability_component_name = [name for name in vulnerability_component_name if isinstance(name, str) and name.strip()]
            

            if isinstance(vulnerability_component_version, list):
                vulnerability_component_version = [version for version in vulnerability_component_version if isinstance(version, str) and version.strip()]
            
            
            

            cve['vulnerability_component_name'] = vulnerability_component_name
            cve['vulnerability_component_version'] = vulnerability_component_version
            cve['vulnerability_component_type'] = vulnerability_component_type

            print(f"Augmented CVE Data:")
            print(f"  Vulnerability Component Name: {cve['vulnerability_component_name']}")
            print(f"  Vulnerability Component Version: {cve['vulnerability_component_version']}")
            print(f"  Vulnerability Component Type: {cve['vulnerability_component_type']}")
            return cve
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON response for CVE ID {cve['cve_id']}: {e}")
            print("LLM Output:")
            print(output_text)
    except Exception as e:
        print(f"Error during LLM processing for CVE ID {cve['cve_id']}: {e}")

    print("-" * 60)

""" async def main():
    cves_augmented = []
    cves = get_filtered_cves(2024, 2024, 5)
    n = 0
    cves = cves[n:]

    for cve in cves:
        augmented_cve = await process_cve_augmentation(cve)
        if augmented_cve:
            cves_augmented.append(augmented_cve)
            # Optional: Add rate limiting here

        # Save the augmented CVEs to a file
        with open('cves_augmented_gpt_2024_10.json', 'w') as f:
            json.dump(cves_augmented, f, indent=2, default=default_serializer)

    print("Completed processing CVEs for OS and affected component with versions extracted.")

if __name__ == "__main__":
    asyncio.run(main()) """
