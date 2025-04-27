## ADCS-Exploitation-Toolkit

A Python-based toolkit for streamlined exploitation of Active Directory Certificate Services (ADCS) vulnerabilities. 
Built for security researchers and penetration testers, this repository automates the exploitation of ADCS misconfigurations in authorized environments.

- - - 

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/dr34mhacks/ADCS-Exploitation-Toolkit
cd ADCS-Exploitation-Toolkit
pip3 install -r requirements.txt

```

## Exploitation Scripts

**ESC1 Exploitation Script**: Automates the ESC1 vulnerability, where misconfigured certificate templates allow arbitrary User Principal Names (UPNs), allowing privilege escalation to Domain Admin.
This script will find the ESC1 vulnerable template and auto simulate the exploitation by auto requesting the `.pfx` of administrator and dumping their TGT and NTLM Hash. The script also verify the NTLM hash via `nxc` tool.


### Usage 

<details>
<summary><b>Arguments</b></summary>
 <br>
<pre>
 -u, --username: Domain username
 -p, --password: Password for the user
 -d, --domain: Domain name
 --dc-ip: Domain controller IP address
 --target-hostname: Target hostname for certipy req (optional)
 --target-upn: Target UPN for the certificate (optional, defaults to administrator, e.g., administrator@retro.vl).
 --template: Manually specify vulnerable template (optional)
 --ca: Manually specify CA name (optional, e.g., retro-DC-CA).
 --debug: Enable verbose Certipy output (optional, default: False).
 --show-commands: Show executed commands (optional, default: False).
 --dump-ntds: Dump NTDS.dit using NetExec (optional, default: False).
</pre>
</details>


**Basic run**

```
 python3 esc1.py -u 'BANKING$' -p 'sidhere' -d retro.vl --dc-ip 10.10.125.203
```

<img width="1134" alt="image" src="https://github.com/user-attachments/assets/7a00d395-e253-43c1-91eb-bc87b3a52ee8" />

**With NTDS Dump**

```bash
python3 esc1.py -u 'BANKING$' -p 'sidhere' -d retro.vl --dc-ip 10.10.125.203 --dump-ntds
```

<img width="1134" alt="image" src="https://github.com/user-attachments/assets/eeca07d7-e00e-40f9-b8e1-6bc4474ae87f" />


## Disclaimer

This toolkit is intended for educational and authorized penetration testing purposes only. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical. The author is not responsible for any misuse or damage caused by these tools. Always obtain proper authorization before testing. Lastly thanks to the [Raj](https://github.com/RajChowdhury240/ADCSDumper) for the idea for this project. 
