**Phishing Email Forensics – sample-2350.eml (PhishingPot)**

**Overview**

This project documents a phishing email forensics workflow using sample-2350.eml from PhishingPot. The goal was to validate whether the message is malicious by analyzing key indicators across headers, authentication records, and infrastructure reputation.

**Tools & Sources Used**

•	VirusTotal – link and domain reputation checks
•	AbuseIPDB – sender IP reputation checks
•	DNS / Email Auth Lookups – SPF, DKIM, DMARC validation
•	Email Header Review – From/Return-Path alignment and routing inspection
________________________________________
**Methodology (6 Factors)**

1) Investigation of links on VirusTotal
I extracted all URLs from the email body (including shortened or redirected links) and checked each one on VirusTotal to identify:
•	malicious or suspicious detections by AV engines
•	domain reputation
•	redirect chains / embedded trackers
•	historical flags and community reports
Outcome recorded: URL verdicts, detection ratios, and any redirect evidence.
[view results](https://github.com/saheed-tech/Phishing-Email-Forensics-sample-2350.eml-PhishingPot-/blob/main/6_virus_total_analysis.PNG)
________________________________________
**2) Investigation of the sender’s IP on AbuseIPDB**

Using the email headers, I identified the originating sender IP (typically from the earliest “Received:” line that represents the first hop) and searched it on AbuseIPDB to assess:
•	abuse confidence score
•	reports category (spam, phishing, botnet, etc.)
•	frequency and recency of reports
•	ISP/ASN context
Outcome recorded: IP reputation summary and abuse confidence.
[view results](https://github.com/saheed-tech/Phishing-Email-Forensics-sample-2350.eml-PhishingPot-/blob/main/7_ipdb_analysis.PNG)
________________________________________
**3) SPF Record Check**

I verified the domain’s SPF policy to confirm whether the sending server was authorized to send email for the domain.
What I checked:
•	SPF result in headers: pass / fail / softfail / neutral
•	which IPs are permitted in SPF
•	whether SPF aligned with the visible “From” domain
Outcome recorded: SPF result and alignment status.
[view results](https://github.com/saheed-tech/Phishing-Email-Forensics-sample-2350.eml-PhishingPot-/blob/main/8_sfp%3Dfail_analysis.PNG)
________________________________________
**4) DKIM Record Check**

I confirmed whether the message was DKIM signed and if the signature validated.
What I checked:
•	presence of DKIM-Signature header
•	dkim=pass/fail results (if provided by the receiving system)
•	signing domain (d=) and selector (s=)
Outcome recorded: DKIM presence + pass/fail and signing domain.
[view results](https://github.com/saheed-tech/Phishing-Email-Forensics-sample-2350.eml-PhishingPot-/blob/main/9_dkim%3Dnone_analysis.PNG)
________________________________________
**5) DMARC Record Check**

I checked whether DMARC was configured for the domain and whether the message passed DMARC evaluation.
What I checked:
•	DMARC result in headers (sometimes in Authentication-Results)
•	domain alignment between:
o	From domain
o	SPF domain (MAIL FROM / Return-Path)
o	DKIM signing domain
•	DMARC policy (p=none/quarantine/reject)
Outcome recorded: DMARC policy and pass/fail status.
[view results](https://github.com/saheed-tech/Phishing-Email-Forensics-sample-2350.eml-PhishingPot-/blob/main/9_dkim%3Dnone_analysis.PNG)
________________________________________
**6) From Path and Return-Path Review**

I compared the visible From address with the Return-Path and other routing headers to detect spoofing or domain mismatch.
What I checked:
•	From: vs Return-Path: domain mismatch
•	reply-to anomalies (Reply-To: different from From)
•	suspicious display name tricks (brand impersonation)
•	inconsistencies across header domains
Outcome recorded: alignment/mismatch notes and spoofing indicators.
[view results](https://github.com/saheed-tech/Phishing-Email-Forensics-sample-2350.eml-PhishingPot-/blob/main/10_from_return_analysis.PNG)
________________________________________
**Findings Summary**

Based on the 6-factor analysis, I documented whether the email shows signs of:
•	spoofing (authentication failures, domain mismatch)
•	malicious infrastructure (bad IP reputation)
•	malicious URLs (VirusTotal detections)
•	misalignment between From / Return-Path (common phishing indicator)
[virustotal results](https://github.com/saheed-tech/Phishing-Email-Forensics-sample-2350.eml-PhishingPot-/blob/main/6_virus_total_analysis.PNG)
[abuseipdb](https://github.com/saheed-tech/Phishing-Email-Forensics-sample-2350.eml-PhishingPot-/blob/main/7_ipdb_analysis.PNG)
[SPF record](https://github.com/saheed-tech/Phishing-Email-Forensics-sample-2350.eml-PhishingPot-/blob/main/8_sfp%3Dfail_analysis.PNG)
[DKIM record](https://github.com/saheed-tech/Phishing-Email-Forensics-sample-2350.eml-PhishingPot-/blob/main/9_dkim%3Dnone_analysis.PNG)
[DMARC record](https://github.com/saheed-tech/Phishing-Email-Forensics-sample-2350.eml-PhishingPot-/blob/main/9_dkim%3Dnone_analysis.PNG)
[from and return](https://github.com/saheed-tech/Phishing-Email-Forensics-sample-2350.eml-PhishingPot-/blob/main/10_from_return_analysis.PNG)


