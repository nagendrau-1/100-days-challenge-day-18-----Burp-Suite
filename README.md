# 100-days-challenge-day-18-----Burp-Suite

Burp Suite. 

I learned how attackers intercept, modify, and replay HTTP requests to manipulate applications.

Burp Suite 

A powerful web application security testing tool widely used by penetration testers, bug bounty hunters, and security researchers.

What is Burp Suite?

Burp Suite is an intercepting proxy that lets you see, modify, and analyze HTTP/HTTPS traffic between your browser and a web application.

Key Features

•	Proxy – Intercept & modify requests/responses

•	Repeater – Manually test and tweak requests

•	Intruder – Automated attacks (bruteforce, fuzzing)

•	Scanner (Pro) – Automated vulnerability scanning

•	Decoder – Encode/decode (Base64, URL, etc.)

•	Comparer – Compare responses to spot differences

 Vulnerabilities You Can Find
 
•	SQL Injection

•	XSS (Cross-Site Scripting)

•	IDOR

•	CSRF

•	Authentication flaws

•	Logic issues

 Versions
 
•	Community – Free, manual testing

•	Professional – Paid, automated scanner

•	Enterprise – Large-scale continuous scanning

How attackers intercept

Attackers intercept traffic mainly by placing themselves between the user and the server — this is called a Man-in-the-Middle (MITM) attack. Below is a clear, step-by-step breakdown 

How Attackers Intercept Network Traffic

1️ Proxy-Based Interception (Most Common)

Attackers configure a proxy (like Burp Suite) between:

•	Browser ↔ Proxy ↔ Server

How it works

•	Victim traffic passes through the proxy

•	Attacker can view, modify, replay requests

Used for

•	Stealing session cookies

•	Modifying parameters

•	Testing authentication & logic flaws

2️ ARP Spoofing (Local Network Attacks)

Attackers poison ARP tables to impersonate:

•	Gateway

•	Victim

Result

•	All traffic flows through the attacker

Common tools

•	Ettercap

•	Bettercap

•	dsniff

 Works mostly on public Wi-Fi / LAN
 
3️ Rogue Wi-Fi (Evil Twin)

Attacker creates a fake Wi-Fi access point:

•	Same name as real Wi-Fi

•	Stronger signal

Victim connects → traffic intercepted

Used to:

•	Capture credentials

•	Inject malicious scripts

•	Force HTTP downgrade

4️  DNS Spoofing

Attacker alters DNS responses:

•	Redirects victim to malicious server

Victim thinks:

•	bank.com is real

But actually hits fake site

5️ SSL Stripping (HTTPS Downgrade)

Attacker forces:

•	HTTPS → HTTP

Victim sees:

•	No padlock 

Traffic becomes plain text

(Modern browsers reduce this, but misconfigurations still exist)

6️ Malicious Browser Extensions

User installs a fake or compromised extension

•	Reads requests

•	Steals cookies

•	Injects JS

Very common in:

•	Password theft

•	Session hijacking

7️ Compromised Devices

If attacker controls:

•	Router

•	Laptop

•	Mobile

They can:

•	Install root certificates

•	Intercept HTTPS traffic silently

Why Interception Works

•	Missing HTTPS

•	Weak Wi-Fi security

•	No certificate validation

•	User trust in public networks

•	Misconfigured applications

How to Defend (Very Important)

•	Always use HTTPS

•	Enable HSTS

•	Use VPN on public Wi-Fi

•	Avoid unknown Wi-Fi networks

•	Verify certificates

•	Use secure cookies (HttpOnly, Secure)

Modify

When attackers intercept traffic, they don’t just read it — they can modify it in transit. Here’s a clear, simple explanation 

How Attackers Modify Intercepted Traffic

Core Idea

Victim → Attacker (modify) → Server

Server → Attacker (modify) → Victim

Because the attacker sits in the middle, they can change requests or responses before forwarding them.

1️ Modifying Requests (Client → Server)

Attackers change data sent by the browser.

 What they modify
 
•	Parameters

price=10 → price=1

•	User roles

role=user → role=admin

•	IDs (IDOR)

user_id=1001 → user_id=1002

•	Hidden fields

•	Headers

o	Cookies

o	Authorization tokens

o	User-Agent

 Impact
 
•	Privilege escalation

•	Free purchases

•	Account takeover

•	Access to other users’ data

2️ Modifying Responses (Server → Client)

Attackers alter what the server sends back.

 What they modify
 
•	Inject malicious JavaScript

•	Remove security warnings

•	Change API responses

•	Bypass frontend validations

 Impact
 
•	Session hijacking

•	Credential theft

•	Fake success messages

•	XSS attacks

3️ Cookie & Session Manipulation

•	Steal session cookies

•	Modify cookie values

•	Remove security flags (Secure, HttpOnly)

 Attacker logs in without a password

4️ HTTPS Interception (Advanced)

If attacker:

•	Installs a fake root certificate

•	Or controls the device/router

They can:

•	Decrypt HTTPS

•	Modify encrypted traffic silently

Why Modification Works

•	Trusting client-side validation

•	No server-side checks

•	Weak authorization logic

•	Missing integrity validation

•	Poor TLS configuration

How to Prevent Modification

•	Validate everything server-side

•	Use HTTPS + HSTS

•	Implement proper authorization

•	Use signed tokens (JWT with validation)

•	Set Secure, HttpOnly, SameSite cookies

•	Detect proxy/MITM behavior

Real-World Practice

This is exactly what tools like Burp Suite Repeater & Proxy demonstrate in DVWA, Juice Shop, PortSwigger labs.

If you want:

•	A Burp Suite step-by-step example

•	Real attack → defense mapping

•	A diagram or Instagram carousel

•	SOC analyst perspective (alerts & logs)

Replay HTTP requests to manipulate applications

Replaying HTTP requests is a common way attackers manipulate how an application behaves by resending (and tweaking) valid requests that the server already trusts.

Below is a clear, conceptual explanation (what happens, why it works, and what it breaks) — not tool instructions.

What Does “Replay HTTP Requests” Mean?

An attacker:

1.	Captures a legitimate request
	
2.	Sends it again (same or modified)
	
3.	The server processes it as valid
	
Because HTTP is stateless, the server often can’t tell:

•	who sent it

•	how many times it was sent

•	whether it was altered

Why Replays Work

Applications often assume:

•	“If the request looks valid, it must be allowed”

•	“The frontend already validated this”

•	“Users won’t resend the same action”

Those assumptions are wrong.

What Attackers Manipulate Using Replays

1️ Business Logic Abuse

•	Re-submit a payment request

•	Re-trigger coupon / discount

•	Repeat refund / reward actions

 Results: free items, money loss

2️ Authorization Bypass

•	Replay a request meant for one user

•	Change only the ID

/api/order?id=1001 → /api/order?id=1002

 Access to other users’ data (IDOR)

3️ Privilege Escalation

•	Capture a request with a hidden field

role=user

•	Replay it as:

role=admin

If server trusts the request → admin access

4️ Rate-Limit & OTP Abuse

•	Replay login or OTP verification requests

•	No server-side tracking

 Brute-force, account takeover

5️ Race Conditions

•	Replay the same request multiple times quickly

•	Server processes them concurrently

 Double spending, duplicate actions

6️ Session Hijacking

•	Replay requests with stolen session cookies

•	No password required

 Full account access

Why Servers Fail to Stop Replays

•	No nonce / request uniqueness

•	Missing timestamp validation

•	No CSRF tokens

•	Weak authorization checks

•	Trust in client-side logic

•	Stateless APIs without integrity checks

How Applications Should Defend

Server-Side Protections

•	Enforce authorization on every request

•	Use nonces / one-time tokens

•	Validate timestamps

•	Implement idempotency keys

•	Detect duplicate requests

•	Proper rate limiting

 Session Security
 
•	Secure, HttpOnly cookies

•	Token rotation

•	Short session lifetimes

 Business Logic Controls
 
•	Track action state (already used? already paid?)

•	Lock critical transactions

•	Validate order & workflow sequence

Why Security Testers Replay Requests

Ethical hackers replay requests to:

•	Test trust boundaries

•	Expose logic flaws

•	Prove real business impact

•	Show developers why frontend checks fail

#BurpSuite 

#WebSecurity

 #EthicalHacking 
 
#CyberSecurity

 #PenetrationTesting

#HTTPRequests

 #RequestInterception 
 
#RequestManipulation 



Academy: SKILLSUPRISE

Mentor: Manojkumar Koravangi



