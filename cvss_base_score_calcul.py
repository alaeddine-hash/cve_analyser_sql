import math

# Dictionary mapping the CVSS vector metrics to their numerical values
METRIC_VALUES = {
    'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
    'AC': {'L': 0.77, 'H': 0.44},
    'PR': {
        'N': {'U': 0.85, 'C': 0.85},
        'L': {'U': 0.62, 'C': 0.68},
        'H': {'U': 0.27, 'C': 0.50}
    },
    'UI': {'N': 0.85, 'R': 0.62},
    'S': {'U': 'U', 'C': 'C'},  # We use 'U' and 'C' directly
    'C': {'H': 0.56, 'L': 0.22, 'N': 0.0},
    'I': {'H': 0.56, 'L': 0.22, 'N': 0.0},
    'A': {'H': 0.56, 'L': 0.22, 'N': 0.0}
}

def parse_vector(cvss_vector):
    """Parse the CVSS vector string into a dictionary."""
    metrics = cvss_vector.strip().split('/')
    parsed = {}
    for metric in metrics[1:]:  # Skip the "CVSS:3.x" part
        key, value = metric.split(':')
        parsed[key] = value
    return parsed

def calculate_iss(C, I, A):
    """Calculate the Impact Sub-Score (ISS)."""
    iss = 1 - (1 - C) * (1 - I) * (1 - A)
    return iss

def calculate_impact(ISS, S):
    """Calculate the Impact sub-score."""
    if S == 'U':  # Scope Unchanged
        impact = 6.42 * ISS
    else:  # Scope Changed
        impact = 7.52 * (ISS - 0.029) - 3.25 * ((ISS - 0.02) ** 15)
    # Ensure Impact is not negative
    return max(impact, 0)

def calculate_exploitability(AV, AC, PR, UI):
    """Calculate the Exploitability sub-score."""
    exploitability = 8.22 * AV * AC * PR * UI
    return exploitability

def roundup_to_nearest_0_1(x):
    """Round up to the nearest 0.1 according to CVSS rules."""
    return math.ceil(x * 10) / 10.0

def calculate_base_score(cvss_vector):
    """Calculate the CVSS v3.1 base score from the CVSS vector."""
    parsed = parse_vector(cvss_vector)

    # Get the values of the vector metrics
    AV = METRIC_VALUES['AV'][parsed['AV']]
    AC = METRIC_VALUES['AC'][parsed['AC']]
    S = parsed['S']
    PR = METRIC_VALUES['PR'][parsed['PR']][S]
    UI = METRIC_VALUES['UI'][parsed['UI']]
    C = METRIC_VALUES['C'][parsed['C']]
    I = METRIC_VALUES['I'][parsed['I']]
    A = METRIC_VALUES['A'][parsed['A']]

    # Calculate ISS
    ISS = calculate_iss(C, I, A)
    #print(f"ISS (Impact Sub-Score): {ISS}")

    # Calculate Impact
    impact = calculate_impact(ISS, S)
    #print(f"Impact: {impact}")

    # Calculate Exploitability
    exploitability = calculate_exploitability(AV, AC, PR, UI)
    #print(f"Exploitability: {exploitability}")

    # Calculate Base Score
    if impact <= 0:
        base_score = 0.0
    else:
        if S == 'U':
            base_score = roundup_to_nearest_0_1(min(impact + exploitability, 10))
        else:
            base_score = roundup_to_nearest_0_1(min(1.08 * (impact + exploitability), 10))

     #print(f"Base Score: {base_score}")
    return base_score
""" 
 # Example usage:
cvss_vector = "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
base_score = calculate_base_score(cvss_vector)
print(f"Final CVSS Base Score: {base_score}") """
