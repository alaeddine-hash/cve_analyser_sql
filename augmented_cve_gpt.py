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
Identify the operating systems affected directly or indirectly by this vulnerability.(if it is component that affect a library or a framework you put the os whoes can hundle (run) it )

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

1. **Operating System Name (os_name):**
   - List all known operating systems affected by this cve. For example: ["Windows", "Linux", "macOS"].((if it is component that affect a library or a framework you put the os whoes can hundle (run) it )Please ensure you specify a known OS. Be certain about this.)
   - If it is not specified, return `null`.

2. **Operating System Version(s) (os_version):**
   - List the corresponding versions of each OS if applicable..(Note: Do not confuse between the component is version and the operating system is version if it is specified.)
   - If not specified, return `null`.

3.!!!ensure that the number of items in os_name and os_version are matched correctly, even when the version ranges may cover multiple entries.!!!

**Output Format:**

Provide your response in valid JSON format with the following structure:

```json
{
  "os_name": ["Operating System Name(s)"] or null,(NOTE : !! Do not confuse between the component is name and the operating system is name)
  "os_version": ["Operating System Version(s)"] or null or all_versions)(Note: Do not confuse between the component is version and the operating system is version)
  "vendor_name": "Extract the vendor name associated with the CVE/null"
}
Important Guidelines:

Do not include any explanations, introductions, or conclusions.

Provide only the JSON object.

Do not include any code block delimiters or language specifiers.

Ensure the JSON is properly formatted and parsable. """

    return prompt

async def process_cve_augmentation(cve):
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
            os_name = result.get('os_name')
            os_version = result.get('os_version')
            vendor_name= result.get('vendor_name')
            cve['advisory_contents'] = ' '
            if isinstance(os_name, list):
                os_name = [name for name in os_name if isinstance(name, str) and name.strip()]
            else:
                os_name = None

            if isinstance(os_version, list):
                os_version = [version for version in os_version if isinstance(version, str) and version.strip()]
            else:
                os_version = None
            
            

            cve['os_name'] = os_name or None
            cve['os_version'] = os_version or None
            cve['vendor_name'] = vendor_name or None

            print(f"Augmented CVE Data:")
            print(f"  OS Name: {cve['os_name']}")
            print(f"  OS Version: {cve['os_version']}")
            print(f"  Vendor Name: {cve['vendor_name']}")
            return cve
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON response for CVE ID {cve['cve_id']}: {e}")
            print("LLM Output:")
            print(output_text)
    except Exception as e:
        print(f"Error during LLM processing for CVE ID {cve['cve_id']}: {e}")

    print("-" * 60)

async def main():
    cves_augmented = []
    cves = get_filtered_cves(2024, 2024, 100)
    n = 90
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

