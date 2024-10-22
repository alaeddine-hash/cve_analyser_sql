# process_cves_api_async.py

import asyncio
import aiohttp

BASE_URL = 'http://localhost:8000'

""" cve_ids = [
    # 2014
    "CVE-2014-0160",  # Heartbleed OpenSSL vulnerability
    "CVE-2014-0224",  # OpenSSL SSL/TLS MITM vulnerability
    "CVE-2014-1776",  # Internet Explorer Use-After-Free (Zero-Day)
    "CVE-2014-3566",  # POODLE SSLv3 vulnerability
    "CVE-2014-6271",  # Shellshock Bash vulnerability
    "CVE-2014-3704",  # Drupal SQL injection (Drupalgeddon)
    "CVE-2014-4114",  # Windows OLE vulnerability (Sandworm)
    "CVE-2014-4113",  # Windows privilege escalation
    "CVE-2014-7169",  # GNU Bash Command Injection Vulnerability
    "CVE-2014-0569",  # Adobe Flash Player Memory Corruption

    # 2015
    "CVE-2015-0311",  # Adobe Flash Player Zero-Day
    "CVE-2015-0313",  # Adobe Flash Player Zero-Day
    "CVE-2015-0336",  # Adobe Flash Player Use-After-Free
    "CVE-2015-0359",  # Adobe Flash Player Memory Corruption
    "CVE-2015-1635",  # HTTP.sys Remote Code Execution Vulnerability
    "CVE-2015-1701",  # Windows Kernel Elevation of Privilege
    "CVE-2015-2426",  # Windows Font Driver vulnerability
    "CVE-2015-2545",  # Microsoft Office Memory Corruption
    "CVE-2015-5119",  # Adobe Flash Player Zero-Day
    "CVE-2015-5122",  # Adobe Flash Player RCE

    # 2016
    "CVE-2016-0189",  # Internet Explorer VBScript Engine RCE
    "CVE-2016-0728",  # Linux Kernel keyring vulnerability
    "CVE-2016-0800",  # DROWN attack on SSL/TLS
    "CVE-2016-1019",  # Adobe Flash Player Type Confusion
    "CVE-2016-2107",  # OpenSSL Padding Oracle vulnerability
    "CVE-2016-4117",  # Adobe Flash Player Zero-Day
    "CVE-2016-5195",  # Dirty COW Linux kernel privilege escalation
    "CVE-2016-7056",  # OpenSSL ChaCha20-Poly1305 Heap Buffer Overflow
    "CVE-2016-1010",  # Adobe Flash Player Memory Corruption
    "CVE-2016-6277",  # WordPress REST API Content Injection

    # 2017
    "CVE-2017-0144",  # WannaCry SMB vulnerability (EternalBlue)
    "CVE-2017-0145",  # SMB vulnerability exploited by EternalChampion
    "CVE-2017-0199",  # Microsoft Office HTA Handler RCE
    "CVE-2017-0261",  # Microsoft Office Memory Corruption
    "CVE-2017-5638",  # Apache Struts vulnerability (Equifax breach)
    "CVE-2017-5715",  # Spectre Variant 2
    "CVE-2017-5753",  # Spectre Variant 1
    "CVE-2017-5754",  # Meltdown
    "CVE-2017-7269",  # IIS WebDAV ScStoragePathFromUrl buffer overflow
    "CVE-2017-11882", # Microsoft Office Memory Corruption Vulnerability

    # 2018
    "CVE-2018-4878",  # Adobe Flash Zero-Day
    "CVE-2018-7600",  # Drupalgeddon 2
    "CVE-2018-8174",  # Windows VBScript Engine RCE
    "CVE-2018-8440",  # Windows ALPC Elevation of Privilege
    "CVE-2018-11776", # Apache Struts Remote Code Execution
    "CVE-2018-13379", # Fortinet VPN Credential Disclosure
    "CVE-2018-15982", # Adobe Flash Player RCE
    "CVE-2018-20250", # WinRAR ACE File Extraction RCE
    "CVE-2018-10561", # Dasan GPON Router Authentication Bypass
    "CVE-2018-10562", # Dasan GPON Router RCE

    # 2019
    "CVE-2019-0708",  # BlueKeep RDP vulnerability
    "CVE-2019-11510", # Pulse Secure VPN Arbitrary File Disclosure
    "CVE-2019-11580", # Atlassian Crowd Server RCE
    "CVE-2019-19781", # Citrix ADC and Gateway Directory Traversal
    "CVE-2019-3396",  # Atlassian Confluence Widget Connector RCE
    "CVE-2019-10149", # Exim Mail Server RCE
    "CVE-2019-18935", # Telerik UI RCE
    "CVE-2019-15107", # Webmin RCE
    "CVE-2019-2725",  # Oracle WebLogic RCE
    "CVE-2019-6340",  # Drupal Remote Code Execution

    # 2020
    "CVE-2020-0601",  # Windows CryptoAPI Spoofing Vulnerability
    "CVE-2020-0688",  # Microsoft Exchange Validation Key RCE
    "CVE-2020-0796",  # SMBGhost Vulnerability
    "CVE-2020-10189", # Zoho ManageEngine RCE
    "CVE-2020-1472",  # Zerologon Vulnerability
    "CVE-2020-5902",  # F5 BIG-IP RCE Vulnerability
    "CVE-2020-3452",  # Cisco ASA and FTD Directory Traversal
    "CVE-2020-1350",  # Windows DNS Server RCE (SigRed)
    "CVE-2020-0796",  # SMBv3 Client/Server RCE
    "CVE-2020-2555",  # Oracle WebLogic RCE

    # 2021
    "CVE-2021-1675",  # Windows Print Spooler RCE (PrintNightmare)
    "CVE-2021-26855", # Microsoft Exchange Server SSRF (ProxyLogon)
    "CVE-2021-26857", # Microsoft Exchange Server RCE
    "CVE-2021-26858", # Microsoft Exchange Server RCE
    "CVE-2021-27065", # Microsoft Exchange Server EoP
    "CVE-2021-21985", # VMware vCenter Server RCE
    "CVE-2021-28482", # Microsoft Exchange Server RCE
    "CVE-2021-34473", # Microsoft Exchange Server RCE
    "CVE-2021-34527", # PrintNightmare LPE/RCE
    "CVE-2021-44228", # Log4Shell Vulnerability

    # 2022
    "CVE-2022-0185",  # Linux Kernel Privilege Escalation (Dirty Pipe)
    "CVE-2022-0847",  # Dirty Pipe Linux Kernel LPE
    "CVE-2022-22965", # Spring4Shell Vulnerability
    "CVE-2022-26134", # Atlassian Confluence RCE
    "CVE-2022-30190", # Follina MSDT Vulnerability
    "CVE-2022-26113", # GitLab CE/EE RCE
    "CVE-2022-1388",  # F5 BIG-IP iControl REST Auth Bypass
    "CVE-2022-40684", # Fortinet Authentication Bypass
    "CVE-2022-20968", # Cisco AnyConnect VPN Arbitrary Code Execution
    "CVE-2022-37969", # Windows Common Log File System Driver EoP

    # 2023
    "CVE-2023-23397", # Microsoft Outlook Privilege Escalation
    "CVE-2023-25136", # OpenSSH Double-Free Vulnerability
    "CVE-2023-27350", # PaperCut MF/NG Unauthenticated RCE
    "CVE-2023-28252", # Windows CLFS Driver Elevation of Privilege
    "CVE-2023-2868",  # Barracuda ESG Zero-Day RCE
    "CVE-2023-32233", # Linux Kernel Netfilter Use-After-Free
    "CVE-2023-34362", # MOVEit Transfer SQL Injection Leading to RCE
    "CVE-2023-3519",  # Citrix Netscaler ADC and Gateway RCE
    "CVE-2023-36884", # Microsoft Office and Windows HTML RCE
    "CVE-2023-42793", # Cisco IOS XE Web UI Command Injection
] """

cve_ids = [
    'CVE-2024-48786',
    'CVE-2024-48784',
    'CVE-2024-48778',
    'CVE-2024-48777',
    'CVE-2024-48776',
    'CVE-2024-48775',
    'CVE-2024-48774',
    'CVE-2024-48773',
    'CVE-2024-48771',
    'CVE-2024-48770',
    'CVE-2024-48769',
    'CVE-2024-48768',
    'CVE-2024-47884',
    'CVE-2024-38365',
    'CVE-2024-8912',
    'CVE-2024-48041',
    'CVE-2024-48040',
    'CVE-2024-48033',
    'CVE-2024-48020',
    'CVE-2024-47353',
    'CVE-2024-47331',
    'CVE-2024-9539',
    'CVE-2024-46532',
    'CVE-2024-44807',
    'CVE-2024-44157',
    'CVE-2024-9859',
    'CVE-2024-47877',
    'CVE-2024-46215',
    'CVE-2024-44734',
    'CVE-2024-44731',
    'CVE-2024-44415',
    'CVE-2024-44414',
    'CVE-2024-44413',
    'CVE-2024-42018',
    'CVE-2024-9046',
    'CVE-2024-8376',
    'CVE-2024-6985',
    'CVE-2024-5474',
    'CVE-2024-4132',
    'CVE-2024-4131',
    'CVE-2024-4130',
    'CVE-2024-4089',
    'CVE-2024-48827',
    'CVE-2024-48813',
    'CVE-2024-47509',
    'CVE-2024-47508',
    'CVE-2024-47507',
    'CVE-2024-47506',
    'CVE-2024-47505',
    'CVE-2024-47504',
    'CVE-2024-47503',
    'CVE-2024-47502',
    'CVE-2024-47501',
    'CVE-2024-47499',
    'CVE-2024-47498',
    'CVE-2024-47497',
    'CVE-2024-47496',
    'CVE-2024-47495',
    'CVE-2024-47494',
    'CVE-2024-47493',
    'CVE-2024-47491',
    'CVE-2024-47490',
    'CVE-2024-47489',
    'CVE-2024-46088',
    'CVE-2024-44730',
    'CVE-2024-44729',
    'CVE-2024-42640',
    'CVE-2024-39563',
    'CVE-2024-39547',
    'CVE-2024-39544',
    'CVE-2024-39534',
    'CVE-2024-39527',
    'CVE-2024-39526',
    'CVE-2024-33582',
    'CVE-2024-33581',
    'CVE-2024-33580',
    'CVE-2024-33579',
    'CVE-2024-33578',
    'CVE-2024-8755',
    'CVE-2024-47875',
    'CVE-2023-42133',
    'CVE-2024-9822',
    'CVE-2024-9818',
    'CVE-2024-9817',
    'CVE-2024-47872',
    'CVE-2024-47871',
    'CVE-2024-47870',
    'CVE-2024-47869',
    'CVE-2024-47868',
    'CVE-2024-47867',
    'CVE-2024-9816',
    'CVE-2024-9815',
    'CVE-2024-9814',
    'CVE-2024-9487',
    'CVE-2024-47168',
    'CVE-2024-47167',
    'CVE-2024-47166',
    'CVE-2024-47165',
    'CVE-2024-47164',
    'CVE-2024-47084'
]


async def process_cve(session, cve_id):
    url = f"{BASE_URL}/analyze"
    try:
        async with session.post(url, json={"cve_id": cve_id}, timeout=360) as response:
            if response.status == 200:
                print(f"Successfully processed {cve_id}")
                result = await response.json()
                # Since results are saved automatically, we don't need to handle them here
                return result
            else:
                text = await response.text()
                print(f"Error processing {cve_id}: {response.status} - {text}")
                return None
    except Exception as e:
        print(f"Exception processing {cve_id}: {e}")
        return None

async def main():
    async with aiohttp.ClientSession() as session:
        for cve_id in cve_ids:
            print(f"Processing {cve_id}")
            await process_cve(session, cve_id)
            # Wait for the processing of the current CVE to finish before moving to the next

if __name__ == '__main__':
    asyncio.run(main())
