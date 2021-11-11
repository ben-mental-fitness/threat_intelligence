# Trickbot Threat Report

## Overview
Trickbot is a trojan, first discovered in September 2016 by Fidelis. It started life as an evolution to the Dyre banking trojan and is a powerful tool used as part of multi-stage attacks. Trickbot is attributed to the Russia-based financially motivated theat group, Wizard Spider.

Trickbot is often used as part of the initial compromise of an organisation through a phishing email with a malicious link or attachment. It is modular with capabilities including: privilege escalation (Mimikatz), lateral movement (EternalBlue), data exfiltration and delivering additional malware (commonly Emotet and Ryuk).

## Timeline
|Date|Source|Notes|
|:---:|:---:|:---|
|September 2016|[Fidel Security](https://fidelissecurity.com/threatgeek/archive/trickbot-we-missed-you-dyre/)|Trickbot first identified as evolution of Dyre banking trojan.|
|July 2017|[IBM Security Intelligence](https://securityintelligence.com/news/trickbot-learns-from-wannacry-and-petya-by-adding-self-spreading-worm-module/)|EternalBlue functionality is added to Trickbot for lateral movement.|
|Summer 2017|[IBM Security Intelligence](https://securityintelligence.com/trickbot-takes-to-latin-america-continues-to-expand-its-global-reach/)|Trickbot is the most used financial trojan this summer after expanding attacks into South America.|
|August 2018 - May 2019|[Lexblog reporting on FBI](https://www.lexblog.com/2019/05/16/fbi-flash-ryuk-ransomware-continues-to-attack-u-s-businesses/)|The FBI have reported more than 100 US companies have been hit by the Ryuk ransomware, commonly used with Trickbot in this time period.|
|March 2019|[CrowdStrike](https://www.crowdstrike.com/blog/wizard-spider-lunar-spider-shared-proxy-module/)|BokBot proxy module is used during Trickbot attack, suggesting collaboration between the two threat groups that run the respective pieces of malware.|
|October 2020|[Microsoft](https://blogs.microsoft.com/on-the-issues/2020/10/12/trickbot-ransomware-cyberthreat-us-elections/)|Co-orodinated effort, led by Microsoft to disrupt half of the Trickbot infrastructure by disabling IP addresses of C2 servers. This was done as a protective measure to minimise cyber disruption during the US presidential elections.|
|November 2020|[Bleeping Computer](https://www.bleepingcomputer.com/news/security/how-ryuk-ransomware-operators-made-34-million-from-one-victim/), [Advintel](https://www.advintel.io/post/anatomy-of-attack-inside-bazarbackdoor-to-ryuk-ransomware-one-group-via-cobalt-strike)|A reported $34 million ransom was paid to attackers for a decryption key. The same group are reported to have earned over $150m in total.|
|December 2020|[The Hacker News](https://thehackernews.com/2020/12/trickbot-malware-gets-uefibios-bootkit.html), [NIST](https://nvd.nist.gov/vuln/detail/CVE-2021-22887#VulnChangeHistorySection)|Trickboot, a UEFI/BIOS module, is added to Trickbot. This allows it to gain persistence that is harder to detect and remove, compared to the previous scheduled task method. Trickboot adds the capability to 'brick' devices through the firmware.|
|June 2021|[The Hacker News](https://thehackernews.com/2021/06/latvian-woman-charged-for-her-role-in.html)|After being arrested in February, Alla Witte, is charged for her alleged role in being a programmer in Wizard Spider, the cybercrime grouped that created Trickbot.|
|October 2021|[The Hacker News](https://thehackernews.com/2021/10/russian-trickbot-gang-hacker-extradited.html)|Vladimir Dunaev is extradited to the US charged in relation to the creation of the Trickbot malware.|

## IoCs and Mitigations

**File based IoCs:**
```
- Creation of files in C:\Windows\User\AppData\Roaming.
- Task is scheduled such as 'Bot' that starts an executable file such as 'Sweezy.exe'.
- If Trickboot is used (in the 32-bit version) permaDll32 and Rwdrv.sys files will be created.
```

```
permaDll32 Hashes:
- md5:    491115422a6b94dc952982e6914adc39
- sha1:   55803cb9fd62f69293f6de21f18fd82f3e3d1d68
- sha256: c1f1bc58456cff7413d7234e348d47a8acfdc9d019ae7a4aba1afc1b3ed55ffa
```

```
Rwdrv.sys Hashes:
- md5:    257483d5d8b268d0d679956c7acdf02d
- sha1:   fbf8b0613a2f7039aeb9fa09bd3b40c8ff49ded2
- sha256: ea0b9eecf4ad5ec8c14aec13de7d661e7615018b1a3c65464bf5eca9bbf6ded3
```

```
YARA Signature:
rule crime_win32_perma_uefi_dll : Module
{
meta:
 author = "@VK_Intel | Advanced Intelligence"
 description = "Detects TrickBot Banking module permaDll"
 md5 = "491115422a6b94dc952982e6914adc39"
strings:
	$module_cfg = "moduleconfig"
	$str_imp_01 = "Start"
	$str_imp_02 = "Control"
	$str_imp_03 = "FreeBuffer"
	$str_imp_04 = "Release"
	$module = "user_platform_check.dll"
	$intro_routine = { 83 ec 40 8b ?? ?? ?? 53 8b ?? ?? ?? 55 33 ed a3 ?? ?? ?? ?? 8b ?? ?? ?? 56 57 89 ?? ?? ?? a3 ?? ?? ?? ?? 39 ?? ?? ?? ?? ?? 75 ?? 8d ?? ?? ?? 89 ?? ?? ?? 50 6a 40 8d ?? ?? ?? ?? ?? 55 e8 ?? ?? ?? ?? 85 c0 78 ?? 8b ?? ?? ?? 85 ff 74 ?? 47 57 e8 ?? ?? ?? ?? 8b f0 59 85 f6 74 ?? 57 6a 00 56 e8 ?? ?? ?? ?? 83 c4 0c eb ??}
condition:
6 of them
}
```

**Mitigations**
- Implement email protections - tag external emails, offer reporting for employees to send suspicious emials to the security/ IT team, block suspicious IPs.  
- Implement internal IDS/IPS systems to detect suspicious activity.
- Patch EternalBlue to restrict lateral movement.
- Verify firmware hashes if there is a suspected infection.

## References
|Source|Notes|
|:---:|:---|
|[NCSC Advisory](https://www.ncsc.gov.uk/news/trickbot-advisory)|Banking trojan designed to obtain PII, but sometimes used to infiltrate a network and deploy other malware. Infection method is through attachments in phishing emails.|
|[CISA Alert](https://us-cert.cisa.gov/ncas/alerts/aa21-076a)|First identified in 2016, Trickbot has been used in numerous attacks. Persistence through scheduled task, hardcoded C2 server, may use EternalBlue for lateral movement.|
|[CISA Fact Sheet](https://us-cert.cisa.gov/sites/default/files/publications/TrickBot_Fact_Sheet_508.pdf)|Fact sheet on Trickbot with references to other resources.|
|[Malwarebytes](https://blog.malwarebytes.com/detections/trojan-trickbot/)|Symptoms (for network admins), IoCs and business remediation.|
|[Microsoft](https://www.microsoft.com/security/blog/2020/10/12/trickbot-disrupted/)|analysis of Trickbot after co-ordinated takedown.|
|[Bleeping Computer](https://www.bleepingcomputer.com/news/security/new-trickbot-campaign-spamming-malicious-complaint-doc-attachments/)|Blog post investigating an early attack utilising Trickbot. Details of the exploit attack-chain and IoCs are provided.|
|[Blueliv Search Results](https://community.blueliv.com/#!/discover?search=trickbot)|Search results for recent content released about Trickbot.|
|[Pulsedive Trickbot Page](https://pulsedive.com/threat/?tid=26)|Overview, properties and IoCs for Trickbot.|
|[MITRE page for Wizard Spider](https://attack.mitre.org/groups/G0102/)|A bio page for Wizard Spider, who created Trickbot in 2016.|
|[CIS](https://www.cisecurity.org/blog/trickbot-not-your-average-hat-trick-a-malware-with-multiple-hats/)|CIS extensive article on Trickbot. Technical details, use-cases, implications and protections.|
|[Eclypsium](https://eclypsium.com/2020/12/03/trickbot-now-offers-trickboot-persist-brick-profit/)|Extensive aritcle on Trickboot functionality.|
