import asyncio
from langchain_openai import ChatOpenAI
from get_cve import get_filtered_cves
from patch_and_mitigation import extract_advisory_links, scrape_urls
import csv  

def create_prompt_cve_classification(cve):
    prompt = f"""
As a cybersecurity expert specializing in vulnerability assessment and familiar with CVSS v3.1, your task is to classify each CVSS base metric** for the given CVE.
You will analyze the CVE details and advisory contents to determine the most accurate value for each metric, based solely on the information provided.

**CVE Details:**
- **CVE ID:** {cve['cve_id']}
- **Description:** {cve['description']}

**Advisory Contents:**
"""
    # Include advisory contents if available
    for advisory in cve.get('advisory_contents', []):
        prompt += f"\n- **URL:** {advisory['url']}\n**Content:**\n{advisory['content']}\n"

    prompt += """
**Instructions:**

1. **Carefully read and analyze** the CVE description and advisory contents provided.

2. **For each CVSS v3.1 base metric**, perform a thorough analysis to determine the most appropriate value based on the information given. Document your reasoning for each metric internally.


   - **Attack Vector (AV):**
     - **N (Network):** The vulnerability is exploitable remotely over a network.
     - **A (Adjacent):** Attack requires access to the local network or subnet.
     - **L (Local):** Attack requires local access to the system.
     - **P (Physical):** Attack requires physical interaction with the device.

   - **Attack Complexity (AC):**
     - **L (Low):** The attack does not require special conditions; it's straightforward.
     - **H (High):** The attack requires specific conditions or configurations.

   - **Privileges Required (PR):**
     - **N (None):** No privileges are required to exploit the vulnerability.
     - **L (Low):** Requires basic user privileges.
     - **H (High):** Requires elevated or administrative privileges.

   - **User Interaction (UI):**
     - **N (None):** No user interaction is required.
     - **R (Required):** Exploitation requires user action (e.g., clicking a link).

   - **Scope (S):**
     - **U (Unchanged):** The impact is confined to the vulnerable component.
     - **C (Changed):** The vulnerability can affect components beyond its security scope.

   - **Confidentiality Impact (C):**
     - **N (None):** No impact on confidentiality.
     - **L (Low):** Limited disclosure of data; attacker gains access to some information.
     - **H (High):** Total information disclosure; all data is compromised.

   - **Integrity Impact (I):**
     - **N (None):** No impact on integrity.
     - **L (Low):** Modification of some data without control over the outcome.
     - **H (High):** Complete loss of integrity; attacker can modify any data.

   - **Availability Impact (A):**
     - **N (None):** No impact on availability.
     - **L (Low):** Reduced performance or interruptions in resource availability.
     - **H (High):** Complete shutdown of the affected component.


**Considerations for Each Metric:**

- **Attack Vector (AV):** Determine if the vulnerability can be exploited remotely (Network), locally, or requires physical access.
- **Attack Complexity (AC):** Assess whether there are any special conditions or configurations required for exploitation.
- **Privileges Required (PR):** Identify the level of privileges an attacker needs to exploit the vulnerability.
- **User Interaction (UI):** Decide if the attack can occur without user interaction or requires a user to perform an action.
- **Scope (S):** Evaluate whether the vulnerability affects only the component or can impact other components.
- **Confidentiality Impact (C):** Consider the extent to which confidentiality is compromised.
- **Integrity Impact (I):** Assess the potential for unauthorized data modification.
- **Availability Impact (A):** Determine the extent to which system availability is affected.

3. **Generate the CVSS vector string** by combining your classifications in the following exact format:
CVSS:3.1/AV:[AV]/AC:[AC]/PR:[PR]/UI:[UI]/S:[S]/C:[C]/I:[I]/A:[A]

**Example:**

**CVE Details:**
- **CVE ID:** CVE-2023-12345
- **Description:** A buffer overflow vulnerability in XYZ application allows remote attackers to execute arbitrary code via a crafted network packet.

**Advisory Contents:**
- **URL:** https://security.com/advisory
**Content:**
The XYZ application version 1.2.3 suffers from a buffer overflow in its network handling code, which can be exploited remotely without authentication.

**Analysis:**
- **Attack Vector (AV):** N (Network)
- **Attack Complexity (AC):** L (Low)
- **Privileges Required (PR):** N (None)
- **User Interaction (UI):** N (None)
- **Scope (S):** U (Unchanged)
- **Confidentiality Impact (C):** H (High)
- **Integrity Impact (I):** H (High)
- **Availability Impact (A):** H (High)

**CVSS Vector:**
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

**Example:**

**CVE Details:**
- **CVE ID:** CVE-2021-44228
- **Description:** A remote code execution vulnerability exists in Apache Log4j versions 2.0-beta9 to 2.14.1. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.

**Advisory Contents:**
- **URL:** https://logging.apache.org/log4j/2.x/security.html
**Content:**
Apache Log4j 2 contains a critical remote code execution (RCE) vulnerability in the JNDI lookup feature. An attacker can exploit this vulnerability by sending a specially crafted string that is logged by Log4j, allowing the loading and execution of malicious code from an attacker-controlled server.

**Analysis:**

- **Attack Vector (AV):** N (Network)
- **Attack Complexity (AC):** L (Low)
- **Privileges Required (PR):** N (None)
- **User Interaction (UI):** N (None)
- **Scope (S):** C (Changed)
- **Confidentiality Impact (C):** H (High)
- **Integrity Impact (I):** H (High)
- **Availability Impact (A):** H (High)

**CVSS Vector:**
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

**Important Guidelines:**

- **Focus on accurate classification**: Ensure each metric is correctly classified based on the provided details.
- **Your response must be only** the CVSS vector string in the exact format provided.
- **Do not add** any introductory or concluding remarks.
- **Do not mention** any tools, external resources, or personal opinions.
"""
    return prompt


def process_cve_classification(cve):
    # Prepare the prompt
    prompt = create_prompt_cve_classification(cve)

    # Initialize the LLM
    llm = ChatOpenAI(
        model_name='gpt-4o-mini',
        temperature=0.0,
    )

    # Get the response from the LLM
    response = llm.invoke(prompt)
    output_text = response.content.strip()

    # Extract the CVSS vector string
    cvss_vector = output_text.strip()

    # Return the CVSS vector
    return cvss_vector

def parse_cvss_vector(cvss_vector):
    metrics = {}
    try:
        parts = cvss_vector.strip().split('/')
        for part in parts[1:]:
            key, value = part.split(':')
            metrics[key] = value
    except Exception as e:
        print(f"Error parsing CVSS vector: {e}")
    return metrics

def compare_cvss_vectors(original_vector, generated_vector):
    original_metrics = parse_cvss_vector(original_vector)
    generated_metrics = parse_cvss_vector(generated_vector)

    comparison = {}
    for metric in ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']:
        original_value = original_metrics.get(metric, None)
        generated_value = generated_metrics.get(metric, None)
        comparison[metric] = {
            'original': original_value,
            'generated': generated_value,
            'match': original_value == generated_value
        }
    return comparison
async def process_cves(cves):
    # Create a list to store the results
    results = []

    for cve in cves:
        print(f"Processing CVE ID: {cve['cve_id']}")

        # Extract advisory links
        references = extract_advisory_links(cve)

        # Scrape the advisory contents asynchronously
        try:
            cve['advisory_contents'] = await scrape_urls(references)
        except Exception as e:
            print(f"Error during advisory scraping: {e}")
            cve['advisory_contents'] = []

        # Get the CVSS vector from the LLM
        generated_cvss_vector = process_cve_classification(cve)

        # Compare with the original CVSS vector (if available)
        original_cvss_vector = cve.get('cvss_vector_v3', None)
        if original_cvss_vector:
            comparison = compare_cvss_vectors(original_cvss_vector, generated_cvss_vector)
            print("\nCVSS Metric Comparison:")
            for metric, values in comparison.items():
                print(f"{metric}: Original={values['original']}, Generated={values['generated']}, Match={values['match']}")
        else:
            print("Original CVSS vector not available.")
            comparison = None  # No comparison if original vector is missing

        print(f"\nGenerated CVSS Vector: {generated_cvss_vector}")
        print("-" * 60)

        # Prepare data to save
        result = {
            'cve_id': cve['cve_id'],
            'original_vector': original_cvss_vector if original_cvss_vector else '',
            'generated_vector': generated_cvss_vector,
        }

        # If comparison is available, include match information
        if comparison:
            for metric in ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']:
                result[f'match_{metric}'] = comparison[metric]['match']
        else:
            # If no comparison, set match columns to empty strings
            for metric in ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']:
                result[f'match_{metric}'] = ''

        # Add the result to the list
        results.append(result)

    # After processing all CVEs, write the results to a CSV file
    fieldnames = ['cve_id', 'original_vector', 'generated_vector'] + [f'match_{metric}' for metric in ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']]

    with open('cvss_comparison_results.csv', 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        # Write the header
        writer.writeheader()

        # Write the data
        for result in results:
            writer.writerow(result)

    print("Results have been saved to cvss_comparison_results.csv")
        
async def main():
    # Retrieve CVEs
    cves = get_filtered_cves(2024, 2024, 10)  # Adjust as needed
    
    # Process the CVEs asynchronously
    await process_cves(cves)

if __name__ == "__main__":
    asyncio.run(main())