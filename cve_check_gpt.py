import asyncio
from decimal import Decimal
import json
from langchain_openai import ChatOpenAI

from cvss_base_score_calcul import calculate_base_score
from cvss_vector_generation import process_cves
from get_cve import get_filtered_cves

import os
from datetime import datetime

from augmented_cve_gpt import extract_advisory_links, scrape_urls

def create_prompt_for_exploitability_metrics(cve):
    cvss_vector_v3 = cve.get('cvss_vector_v3')
    if not cvss_vector_v3:
        print(f"No CVSS vector available for CVE ID {cve['cve_id']}. Skipping.")
        return None  # No CVSS vector available

    prompt = f"""
You are a cybersecurity analyst with expertise in CVSS scoring and vulnerability assessment. Your task is to analyze the following CVE, focusing on the exploitability metrics in its CVSS vector.

**CVE Details:**

- **CVE ID:** {cve['cve_id']}
- **Description:** {cve['description']}
- **CVSS Vector V3:** {cvss_vector_v3}

**Advisory Contents:**
"""
    # Include advisory contents if available
    for advisory in cve.get('advisory_contents', []):
        prompt += f"\n- **URL:** {advisory['url']}\n**Content:**\n{advisory['content']}\n"

    prompt += """

**Instructions:**

1. **Extract the exploitability metrics from the provided CVSS vector. The exploitability metrics are:**

    - **Attack Vector (AV)**
    - **Attack Complexity (AC)**
    - **Privileges Required (PR)**
    - **User Interaction (UI)**
    - **Scope (S)**

2. **For each metric:**

    - **Provide the value from the CVSS vector.**
    - **Assess whether the value is appropriate given the description of the CVE. If there is any discrepancy, explain it.**(important: I need a real justification from the description, the content of the advisory links, or clear rules in cybersecurity from your knowledge!)
    - **Provide a justification for your assessment.!!! important you will specifie your source : cve_description/advisory_content/knowledge_rules***
    - **Provide the new value like correction if it is Inappropriate**

3. **Provide an overall assessment of the exploitability of the vulnerability based on the metrics and the CVE description.**

**Output Format:**

Provide your response in valid JSON format as follows (do not include any code block delimiters or language specifiers):

{{
  "cve_id": "{cve['cve_id']}",
  "exploitability_metrics": {{
    "AV": {{
      "value": "Value from CVSS vector",
      "assessment": "Appropriate/Inappropriate",
      "llm_value": "Provide the new value like correction if it is Inappropriate",
      "remarks": "Justification from the description (important: I need a real justification from the description, the content of the advisory links, or clear rules in cybersecurity from your knowledge!)",
      "Justification": "important you will specifie your source : cve_description/advisory_links_content/knowledge_rules"
    }},
    "AC": {{
      "value": "Value from CVSS vector",
      "assessment": "Appropriate/Inappropriate",
      "llm_value": "Provide the new value like correction if it is Inappropriate",
      "remarks": "Justification from the description (important: I need a real justification from the description, the content of the advisory links, or clear rules in cybersecurity from your knowledge!)",
      "Justification": "important you will specifie your source : cve_description/advisory_links_content/knowledge_rules"
    }},
    "PR": {{
      "value": "Value from CVSS vector",
      "assessment": "Appropriate/Inappropriate",
      "llm_value": "Provide the new value like correction if it is Inappropriate",
      "remarks": "Justification from the description (important: I need a real justification from the description, the content of the advisory links, or clear rules in cybersecurity from your knowledge!)",
      "Justification": "important you will specifie your source : cve_description/advisory_links_content/knowledge_rules"
    }},
    "UI": {{
      "value": "Value from CVSS vector",
      "assessment": "Appropriate/Inappropriate",
      "llm_value": "Provide the new value like correction if it is Inappropriate",
      "remarks": "Justification from the description (important: I need a real justification from the description, the content of the advisory links, or clear rules in cybersecurity from your knowledge!)",
      "Justification": "important you will specifie your source : cve_description/advisory_links_content/knowledge_rules"
    }},
    "S": {{
      "value": "Value from CVSS vector",
      "assessment": "Appropriate/Inappropriate",
      "llm_value": "Provide the new value like correction if it is Inappropriate",
      "remarks": "Justification from the description (important: I need a real justification from the description, the content of the advisory links, or clear rules in cybersecurity from your knowledge!)",
      "Justification": "important you will specifie your source : cve_description/advisory_links_content/knowledge_rules"
    }}
  }},
  "overall_assessment": "Overall assessment of exploitability",
  "remarks": "Any additional remarks or conclusions"
}}

**Important Guidelines:**

- **Do not include** any explanations or text outside the JSON object.
- **Provide only** the JSON object.
- **Ensure** the JSON is properly formatted and parsable.
"""
    return prompt


def default_serializer(obj):
    """ Custom serializer to handle non-serializable objects like datetime and Decimal """
    if isinstance(obj, datetime):
        return obj.isoformat()  # Convert datetime to ISO format
    elif isinstance(obj, Decimal):
        return float(obj)  # Convert Decimal to float for JSON serialization
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

async def process_cve_exploitability_metrics(cve):
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
    prompt = create_prompt_for_exploitability_metrics(cve)
    if not prompt:
        processed_cve = await process_cves([cve])
        cve['advisory_contents'] = ' '
        cve['generated_cvss_vector'] = processed_cve
        cve['generated_cvss_score'] = calculate_base_score(processed_cve)
        return cve  # Skip if no prompt (e.g., CVSS vector missing)

    # Call the LLM
    try:
        # Initialize the LLM
        llm = ChatOpenAI(
            model_name='gpt-4o-mini',
            temperature=0.0,
            top_p=1.0,        # Full probability distribution
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
            output_text = output_text.replace('{{', '{').replace('}}', '}')
            result = json.loads(output_text)
            # Update the CVE with new attributes
            cve['exploitability_metrics'] = result.get('exploitability_metrics')
            cve['overall_assessment'] = result.get('overall_assessment')
            cve['remarks'] = result.get('remarks')
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


async def main():
    cves_with_exploitability = []
    cves = get_filtered_cves(2024, 2024, 110)  # Adjust the parameters as needed
    n = 90  # Number of CVEs to skip
    cves = cves[n:]  # Remove the first n CVEs

    for cve in cves:
        augmented_cve = await process_cve_exploitability_metrics(cve)
        
        if augmented_cve:
            augmented_cve['advisory_contents'] = ' '
            cves_with_exploitability.append(augmented_cve)

    # Optionally, save the augmented CVEs to a file or database
    with open('cves_with_exploitability_6.json', 'w') as f:
        json.dump(cves_with_exploitability, f, indent=2, default=default_serializer)

    print("Completed processing CVEs for exploitability metrics.")
