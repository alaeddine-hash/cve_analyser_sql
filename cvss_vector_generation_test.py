import asyncio
from langchain_openai import ChatOpenAI
from get_cve import get_filtered_cves
from patch_and_mitigation import extract_advisory_links, scrape_urls

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

2. **Classify each CVSS v3.1 base metric** by selecting the most appropriate value based on the information given and the previous analysis. 
Use only the single-letter abbreviations provided.

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

3. **Generate the CVSS vector string** by combining your classifications in the following exact format:
CVSS:3.1/AV:[AV]/AC:[AC]/PR:[PR]/UI:[UI]/S:[S]/C:[C]/I:[I]/A:[A]

**Important Guidelines:**

- **Focus on accurate classification**: Ensure each metric is correctly classified based on the provided details.
- **Use only** the single-letter abbreviations specified (e.g., N, L, H).
- **Do not include** any additional text, explanations, or reasoning in your response.
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

        print(f"\nGenerated CVSS Vector: {generated_cvss_vector}")
        print("-" * 60)
        #return generated_cvss_vector
    
async def main():
    # Retrieve CVEs
    cves = get_filtered_cves(2024, 2024, 10)  # Adjust as needed
    
    # Process the CVEs asynchronously
    await process_cves(cves)

if __name__ == "__main__":
    asyncio.run(main()) 
