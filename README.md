## SAP security audit and penetration testing

Training course materials and research notes that I created to teach how to perform a technical security audit and penetration test of SAP (hosted on-premises).

### Table of contents
- [Intro - List of useful tools and resources](#Intro---List-of-useful-tools-and-resources)
- Security Audit
	- [1. SAP security controls and configuration hardening review](#1-SAP-security-controls-and-configuration-hardening-review)
	- [2. SAP user and access management review](#2-SAP-User-and-Access-Management-Review)
	- [3. Risks of having the ABAP Debugger enabled in production environment](#3-Risks-of-having-the-ABAP-Debugger-enabled-in-production-environment)
   	- [4. Sensitive information disclosure from SAP Spool](#4-Sensitive-information-disclosure-from-SAP-Spool)
   	- [5. Development kits and transactions](#5-Development-Kits-and-Transactions)
   	- [6. SAP Hana database security configuration review](#6-SAP-Hana-Database-Security-Configuration-Review)
 - Penetration Test
	- [1. How to get unauthorized access to SAP tables and data using SAP transactions](#1-How-to-get-unauthorized-access-to-SAP-tables-and-data-using-SAP-transactions)
	- [2. How to get remote OS commands execution using SAP transactions](#2-How-to-get-remote-OS-commands-execution-using-SAP-transactions)
	- [3. Bypassing security controls with the ABAP Debugger](#3-Bypassing-security-controls-with-the-ABAP-Debugger)
	- [4. SAP penetration testing using NMAP and the Metasploit framework](#4-SAP-penetration-testing-using-NMAP-and-the-Metasploit-framework)

----------------
### Intro - List of useful tools and resources
```
Useful tools for auditing SAP
—————————————————————————————
➤ SAPgui - GUI client for SAP ERP (https://community.sap.com/topics/gui)
➤ Database clients (e.g. HDBSQL, sql*plus)
➤ NMAP - Network port scanner (https://nmap.org)
➤ Metasploit penetration testing framework (https://www.metasploit.com) 
➤ 'John the Ripper' - Password cracker (https://www.openwall.com/john/)
➤ Hashcat - Password cracker (https://hashcat.net/hashcat/)
➤ Various scripts (source:kali/Github/your owns)
```
```
Useful resources regarding SAP security
———————————————————————————————————————
➤ SAP provides multiple security guides:
  - Security Guide for SAP S/4HANA 2022 (dating from 2023-11-15)
    ➤ https://help.sap.com/doc/d7c2c95f2ed2402c9efa2f58f7c233ec/2022/en-US/SEC_OP2022.pdf
  - Security Guide for SAP S/4HANA 2021 (dating from 2023-11-08)
    ➤ https://help.sap.com/doc/d7c2c95f2ed2402c9efa2f58f7c233ec/2021/en-US/SEC_OP2021.pdf
  - SAP NetWeaver Security Guide
    ➤ https://help.sap.com/docs/SAP_NETWEAVER_AS_ABAP_FOR_SOH_740/621bb4e3951b4a8ca633ca7ed1c0aba2/4aaf6fd65e233893e10000000a42189c.html
  - Protect Your SAP S/4HANA Cloud (Security Recommendations)
    ➤ https://help.sap.com/docs/SAP_S4HANA_CLOUD/55a7cb346519450cb9e6d21c1ecd6ec1/52a1403b71464a8580bc2211b7ce0e32.html?locale=en-US
  - SAP HANA Security (dating from 2021)
    ➤ https://www.sap.com/documents/2016/06/3ea239ad-757c-0010-82c7-eda71af511fa.html
  - Security Whitepapers
    ➤ https://support.sap.com/en/security-whitepapers.html
  - SAP Security Operations On Azure (Blog post)
    ➤ https://community.sap.com/t5/enterprise-resource-planning-blogs-by-members/sap-security-operations-on-azure/ba-p/13403609
  - SAP Help Portal (Documentation)
    ➤ https://help.sap.com/docs/

➤ Azure Cloud and SAP
  - Security operations for SAP on Azure
    ➤ https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/scenarios/sap/sap-lza-security-operations
  - Introduction to an SAP adoption scenario
    ➤ https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/scenarios/sap/

➤ AWS Cloud and SAP
  - How to migrate, implement, configure, and operate SAP solutions on AWS
    ➤ https://docs.aws.amazon.com/sap/latest/sap-netweaver/sec-orc-sap-nw-lx.html
    ➤ https://aws.amazon.com/fr/sap/docs/

➤ Operating System Security Hardening Guide for SAP HANA for SUSE Linux Enterprise Server 
  - https://documentation.suse.com/sbp/sap-15/html/OS_Security_Hardening_Guide_for_SAP_HANA_SLES15/index.html
```
--------

## I - SAP Security Audit 

--------

### 1. SAP security controls and configuration hardening review

<i/>1.1 - SAP Security controls (CoBIT)</i>
> Check that the following technical security controls are implemented.
```
- The superuser "SAP*" is properly secured
- The default passwords for users "DDIC", "SAPCPIC" and "EarlyWatch" have been changed
- The powerful profiles are restricted (SAP_ALL, SAP_NEW)
- Logging & monitoring activities are in place for use of powerful accounts and profiles
- Changes made to the data dictionary are authorized and reviewed regularly
- Log and trace files are appropriately configured and secured
- SAP ERP Remote Function Call (RFC) and Common Programming Interface — Communications (CPI-C) are secured
- Access to information and information systems is restricted
- Information systems processing is protected physically from unauthorized access and from accidental or deliberate loss or damage
- Information processing can be recovered and resumed after operations have been interrupted
- Critical user activities can be maintained and recovered following interruption
- Configuration changes are made in the development environment and transported to production
- Changes to critical number ranges are controlled
- Access to system and customizing tables is narrowly restricted
- Application modifications are planned, tested and implemented in a phased manner
- Customized ABAP/4 programs are secured appropriately
- Batch processing operations are secured appropriately
- Critical and sensitive transaction codes are locked in production
- Strong password management for system users
- SAP Router is configured to act as a gateway to secure communications
- Remote access by software vendors is controlled adequately
```

<i/> 1.2 - Review the SAP network encryption settings - Secure Network Communications (SNC)</i>
> SAP Secure Network Communications (SNC)
```
> SNC protects the data communication paths between the various client and server components of the SAP system that use the SAP protocols RFC or DIAG.
> There are well-known cryptographic algorithms that have been implemented by the various security products, and with SNC, you can apply these algorithms to your data for increased protection.
> With SNC, you receive application-level, end-to-end security. All communication that takes place between two SNC-protected components is secured (for example, between the SAP GUI for Windows and the application server).
> There are three levels of security protection you can apply. They are:
  + Authentication only
  + Integrity protection
  + Privacy protection
```
> To audit the SNC settings, you can use the transaction code "SNC" that displays the current SNC settings configured for the SAP system. You can also review the "RSPARAM" report (Use the Tcode SA38 and then enter RSPARAM) which provides an overview of various system parameters, including those related to SNC.
```
List of SNC settings displayed in the RSPARAM report
====================================================

Parameter name			     Description
———————————————————————————————————————————————————————————————————————————————————————————
* rdisp/max_snc_hold_time            Maximum hold time while priv SNC                                                
* rdisp/snc_no_commit                SNC uses a non-commit send mode                                                 
* rdisp/use_snc_refresh              Should we use the SNC refresh
* snc/accept_insecure_cpic           Accept insecure CPIC-connections to SNC-enabled Server                          
* snc/accept_insecure_gui            Accept insecure SAPGUI logins to SNC-enabled Server                             
* snc/accept_insecure_r3int_rfc      Accept insecure internal RFCs on SNC-enabled Server                             
* snc/accept_insecure_rfc            Accept insecure RFC-connections to SNC-enabled Server                           
* snc/data_protection/max            Limit for data protection of Secure Network Comm.                               
* snc/data_protection/min            Min. required data protection for incoming connections                          
* snc/data_protection/use            Level of data protection for R/3 initiated connections                          
* snc/enable                         Enable SNC-Module (Secure Network Communications)                               
* snc/force_login_screen             Display login screen for each SNC-protected login                               
* snc/gssapi_lib                     Filename for external GSS-API shared library                                    
* snc/identity/as                    Name of application server for external Security Syst.                          
* snc/log_unencrypted_rfc            Security Audit Logging for unencrypted RFC connections                          
* snc/only_encrypted_gui             Enforce encrypted SAPGUI connections                                            
* snc/only_encrypted_rfc             nforce encrypted RFC connections                                               
* snc/permit_insecure_start          Permit to start insecure programs when SNC is enabled                           
* snc/r3int_rfc_qop                  Quality of protection for internal RFCs with SNC                                
* snc/r3int_rfc_secure               Use SNC for internal RFC-Communications                                         
* spnego/construct_SNC_name          Construct SNC name for given Kerberos User Name                                 

Other SNC parameters (examples)
> ccl/snc/client_accepted_signature_algorithms    	SHA256_DSA:PKCS_BT_01_SHA256_RSA:PKCS_BT_01_SHA512_RSA:PKCS_
> ccl/snc/client_cipher_suites				HIGH
> ccl/snc/client_protocol 				2010_1_1:2010_1_0
> ccl/snc/server_accepted_signature_algorithms		SHA256_DSA:PKCS_BT_01_SHA256_RSA:PKCS_BT_01_SHA512_RSA:PKCS_
> ccl/snc/server_cipher_suites 				IGH
> ccl/snc/server_protocol 				2010_1_1:2010_1_0 
> ccl/snc/server_session_key_types			ECDSA_P256:ECDSA_P384:ECDSA_P521
```

<i/> 1.3 - Review the SAP security policy settings for logon and password </i>
> In SAP systems, it is possible to create multiple security policies and assign them to users or roles. Security policies can define various parameters related to password complexity, expiration, lockout criteria, and other security-related logon settings. The transaction code for creating and managing security policies is "SECPOL" and the tables that store the configuration settings and the definition of security policies are "SCPOL" and "SECPOL_ATTR". Once a security policy is assigned to a user master record (table USR02), this determines the desired behavior.

> To audit the SAP security policy settings, collect and review the "RSPARAM" report (Use the Tcode SA38 and then enter RSPARAM) which provides an overview of various profile & system parameters, including those that manage password policies and logon settings. Please note, that the profile parameters showed in the "RSAPARAM" report are only relevant for the user master records for which no security policy has been assigned i.e. accounts for which the field "SECURITY_POLICY" is empty in the table "USR02".
```
List of parameters related to logon and password policies displayed in the RSPARAM report
==========================================================================================

Parameters						Description
————————————————————————————————————————————————————————————————————————————————————————————————
* login/accept_sso2_ticket                        	Accept SSO tickets for this (component) system                                  
* login/certificate_mapping_rulebased             	enable / disable rule-based X.509 certificate mapping                           
* login/certificate_request_ca_url                	URL of the certificate authority (for certificate requests)                     
* login/certificate_request_subject               	Template for the subject of a certificate request                               
* login/create_sso2_ticket                        	Create SSO tickets on  this  system                                             
* login/disable_cpic                              	Disable Incoming CPIC Communications                                            
* login/disable_multi_gui_login                   	disable multiple sapgui logons (for same SAP account)                           
* login/disable_password_logon                    	login/disable_password_logon                                                    
* login/failed_user_auto_unlock                   	Enable automatic unlock off locked user at midnight                             
* login/fails_to_session_end                      	Number of invalid login attempts until session end                              
* login/fails_to_user_lock                        	Number of invalid login attempts until user lock                                
* login/isolate_rfc_system_calls                  	isolate RFC system calls                                                        
* login/logon_category_restriction                	Logon Restriction based on Logon Category                                       
* login/min_password_diff                         	min. number of chars which differ between old and new password                  
* login/min_password_digits                       	min. number of digits in passwords                                              
* login/min_password_letters                      	min. number of letters in passwords                                             
* login/min_password_lng                          	Minimum Password Length                                                         
* login/min_password_lowercase                    	minimum number of lower-case characters in passwords                            
* login/min_password_specials                     	min. number of special characters in passwords                                  
* login/min_password_uppercase                    	minimum number of upper-case characters in passwords                            
* login/multi_login_users                         	list of exceptional users: multiple logon allowed                               
* login/no_automatic_user_sapstar                 	Control of the automatic login user SAP*                                        
* login/password_change_for_SSO                   	Handling of password change enforcements in Single Sign-On situations           
* login/password_change_waittime                  	Password change possible after # days (since last change)                       
* login/password_charset                          	character set used for passwords                                                
* login/password_compliance_to_current_policy     	current password needs to comply with current password policy                   
* login/password_downwards_compatibility          	password downwards compatibility (8 / 40 characters, case-sensitivity)          
* login/password_expiration_time                  	Dates until password must be changed                                            
* login/password_hash_algorithm                   	encoding and hash algorithm used for new passwords                              
* login/password_history_size                     	Number of records to be stored in the password history                          
* login/password_logon_usergroup                  	users of this group can still logon with passwords                              
* login/password_max_idle_initial                 	maximum #days a password (set by the admin) can be unused (idle)                
* login/password_max_idle_productive              	maximum #days a password (set by the user) can be unused (idle)                 
* login/password_max_new_valid                    	-                                                                                
* login/password_max_reset_valid                  	-                                                                                
* login/protocol_blocked_secsess_creation         	Protocol blocked security session creation                                      
* login/server_logon_restriction                  	Server Logon Restriction                                                        
* login/show_detailed_errors                      	show detailed login error messages                                              
* login/system_client                             	System default client                                                           
* login/ticket_expiration_time                    	login/ticket_expiration_time                                                    
* login/ticket_only_by_https                      	generate ticket that will only be sent via https                                
* login/ticket_only_to_host                       	ticket will only be sent back to creating host                                  
* login/ticketcache_entries_max                   	maximim number of entries for the SAP Logon Ticket cache                        
* login/ticketcache_off                           	switch off caching for the SAP Logon Ticket                                     
* login/update_logon_timestamp                    	update frequency / accuracy of logon timestamp                                  

NOTE: if multi-login is disabled some users can still be permitted multiple logins via the “login/multi_login_users” setting where user-ids
      can be listed which can be permitted to logon multiple times
```

> Check if multiple security policies have been created and audit them (if any) by reviewing the content of the tables "SECPOL" & "SECPOL_ATTR". In addition, if multiple security policies have been created, audit which security policy is assigned to each user by looking at the field "SECURITY_POLICY" in the table "USR02" (tcode SE16/SE16n).
```
Example of data stored in the SCPOL table
==========================================

POLICY_NAME	DESCRIPTION			MIN_PASSWORD_LENGTH	PASSWORD_EXPIRATION_TIME	PASSWORD_COMPLEXITY	LOCKOUT_THRESHOLD	LOCKOUT_DURATION
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
POLICY_STANDARD	Standard security policy	8			90				Yes			5			30
POLICY_ADMIN	Admin security policy		12			30				Yes			3			60


Example of data stored in the SECPOL_ATTR table
================================================

Password rules
Security policy attribute	Corresponding profile parameter	 Description
------------------------------------------------------------------------------------------------
CHECK_PASSWORD_BLACKLIST	( none )			Check the password blacklist
MIN_PASSWORD_DIGITS		login/min_password_digits	Minimum number of digits
MIN_PASSWORD_LENGTH		login/min_password_lng		Minimum password length
MIN_PASSWORD_LETTERS		login/min_password_letters	Minimum number of letters
MIN_PASSWORD_LOWERCASE		login/min_password_lowercase	Minimum number of lowercase letters
MIN_PASSWORD_SPECIALS		login/min_password_specials	Minimum number of special characters
MIN_PASSWORD_UPPERCASE		login/min_password_uppercase	Minimum number of uppercase letters

Password change policies
Security policy attribute		Corresponding profile parameter	 Description
------------------------------------------------------------------------------------------------
MIN_PASSWORD_CHANGE_WAITTIME		login/password_change_waittime			Minimum wait time for password change
MIN_PASSWORD_DIFFERENCE			login/min_password_diff				No. of different characters when changing
PASSWORD_CHANGE_FOR_SSO			login/password_change_for_SSO			Password change requirement for SSO logons
PASSWORD_CHANGE_INTERVAL		login/password_expiration_time			Interval for regular password changes
PASSWORD_COMPLIANCE_TO_CURRENT_POLICY	login/password_compliance_to_current_policy	Password change after rule tightening
PASSWORD_HISTORY_SIZE			login/password_history_size			Size of the password history

Logon restrictions
Security policy attribute		Corresponding profile parameter	 	Description
------------------------------------------------------------------------------------------------
DISABLE_PASSWORD_LOGON			login/disable_password_logon,    	Disable password logon
					login/password_logon_usergroup		
DISABLE_TICKET_LOGON			( none )				Disable ticket logon
MAX_FAILED_PASSWORD_LOGON_ATTEMPTS	login/fails_to_user_lock		Maximum number of failed attempts
MAX_PASSWORD_IDLE_INITIAL		login/password_max_idle_initial		Validity of unused initial passwords
MAX_PASSWORD_IDLE_PRODUCTIVE		login/password_max_idle_productive	Validity of unused productive passwords
PASSWORD_LOCK_EXPIRATION		login/failed_user_auto_unlock		Automatic expiration of password lock

```
> Other useful check:  SUIM: “Users > by Complex Selection Criteria” or “Users > by Logon Date and Password Change”

<i/> 1.4 - SAP password hash brute-force exercise </i>
> Assess the robustness of SAP passwords by collecting a copy of the USR02 table and then performing password dictionary and brute-force attacks.
  2 well knwon password cracking tools can be used: "John" or "HashCat".

```
SAP Password Hash Formats in the table USR02
————————————————————————————————————————————
+ B/D = "BCODE" hash (MD5-based; Maximum pwd length=8, only upper case ASCII (B) or UTF-8 (D) characters)
+ F = "PASSCODE" hash (SHA1-based with fixed SALT; Maximum pwd length=40, case sensitive)
+ H = "PWDSALTEDHASH" hash (SHA1-based or SHA512-based with random SALT, Maximum pwd length=40, case sensitive)

Notes:
If the field "CODVN" = « G » then the password code versions/formats will be B & F
If the field "CODVN" = « I » then the password code versions/formats will be B, F & H


Example of SAP password hash cracking with the tool "John"
——————————————————————————————————————————————————————————
1. Command to crack "BCODE" hashes
   $ john   --format=sapb   --wordlist=wordlist_file   --rules=all   --fork=10   hashes_file.txt

2. Command to crack "PASSCODE" hashes
   Required hash file format:  username:username$hash
   $ john   --format=sapg   --wordlist=wordlist_file   --rules=all   --fork=10   hashes_file.txt

3. Command to crack "PWDSALTEDHASH" hashes
   Required hash file formats:  
    > example for SHA-1 hashes: username:{x-issha, 1024}hash
    > example for SHA-512 hashes: username:{x-isSHA512, 15000}hash 
   $ john   --format=saph   --wordlist=wordlist_file   --rules=all   --fork=10   hashes_file.txt


Example of SAP password hash cracking with the tool "Hashcat"
—————————————————————————————————————————————————————————————
1. Command to crack "BCODE" hashes
   $ hashcat   -a 0   -m 7700   hashes_file   wordlist_file

2. Command to crack "PASSCODE" hashes
   $ hashcat   -a 0   -m 7800   hashes_file   wordlist_file

3. Command to crack "PWDSALTEDHASH" hashes
   $ hashcat   -a 0   -m 10300   hashes_file   wordlist_file
```

> Please note that 4 SAP tables contain password hashes: USR02, USH02, USRPWDHISTORY, USH02_ARC_TMP. Do not forget about views VUSER001 and VPWD_USR02 containing password hashes too.
```
> USR02: Contains the current user master record including the hash value(s) of the active password
> USH02: Contains the change documents for the user master records including the hash value(s) of former SAP passwords
> USRPWDHISTORY: Contains the user password history of every user
> USH02_ARC_TMP: Used temporarily during archiving of user change documents
```

<i/> 1.5 - Check that the SAP default passwords have been changed </i>
> If you can't do a SAP password hash brute-force exercise (check 1.4), at least verify manually or using a script that the default logins and passwords have been changed.
```
+ List of default SAP accounts and passwords
  
  Login		Password		Clients/Mandants
  ————————————————————————————————————————————————————————————
  SAP* 		PASS or 06071992   	000, 001, 066  
  DDIC 		19920706		000, 001
  TSMADM 	PASSWORD		000, 001
  EARLYWATCH 	SUPPORT			066
  SAPCPIC 	ADMIN   		000, 001
  SAPR3 	SAP 			(SAP Local Database)

  RISK 				USER 				PASSWORD 				CLIENT/Mandants 	REMARK
  ——————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————
  Very High 			SAP* 				06071992 / PASS 			001,066,etc… 		Hardcoded kernel user
  Very High 			IDEADM 				admin					Almost all IDES		clients Only in IDES systems
  Very High 			DDIC 				19920706 				000,001,… 		User has SAP_ALL
  High 				CTB_ADMIN 			sap123 					N.A. 			Java user
  High 				EARLYWATCH 			SUPPORT 				066			Has rights to get password hash for SAP* from USR02 table and sometimes OS execution
  Medium 			 TMSADM				PASSWORD / $1Pawd2&     		000, 			sometimes copied to others
  Medium /Low 			SAPCPIC 			ADMIN 					000,001			Can be used for information retrieval and in some cases for vulnerabilities where only uthentication is needed
																					
  RISK 				USER 				TYPE 				PASSWORD 				SOLMAN SATELLITE
  ———————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————
  HIGH 				SMD_ADMIN 			System 				init1234 				X
  HIGH 				SMD_BI_RFC 			System 				init1234 				X
  HIGH 				SMD_RFC 			System 				init1234 				X
  HIGH 				SOLMAN_ADMIN 			Dialog 				init1234 				X
  HIGH 				SOLMAN_BTC 			System 				init1234 				X
  HIGH 				SAPSUPPORT 			Dialog 				init1234 				X 
  HIGH 				SOLMAN<SID><CLNT> 		Dialog 				init1234 				X
  MED/HIGH 			SMDAGENT_<SID> 			System 				init1234 				X 
  MED 				CONTENTSERV 			System 				init1234 				X
  MED 				SMD_AGT 			System 				init1234    
```

<i/> 1.6 - Standard Security Reports to run (RSUSR via AID, SA38, or SUIM) </i>
```
> RSUSR003 – Check passwords for SAP* and DDIC 
> RSUSR006 – locked users / unsuccessful login attempts
> RSUSR200 - Users with original passwords, users not logged in for xx days, users who have not changed password in xx days
> RSUSR002 - Can be used to determine who has access to powerful BASIS transactions such as the following
```

<i/> 1.7 - Review the SAP Gateway Security Files (SECINFO and REGINFO)</i>
```
> The "secinfo" security file is used to prevent unauthorized launching of external programs.
> The file "reginfo" controls the registration of external programs in the gateway. 
> Useful transaction to display and edit the files = SMGW 

You can define the file path using profile parameters gw/sec_info and gw/reg_info.
The default value is:
> gw/sec_info = $(DIR_DATA)/secinfo
> gw/reg_info = $(DIR_DATA)/reginfo
```
```
Example of a SECINFO file in new syntax
———————————————————————————————————————
#VERSION=2
D HOST=* USER=* TP=/bin/sap/cpict4				//Program cpict4 is not permitted to be started.
P HOST=* USER=* TP=/bin/sap/cpict*				//All other programs starting with cpict4 are allowed to be started (on every host and by every user).
P TP=hugo HOST=local USER=*					//Program hugo is allowed to be started on every local host and by every user.
P TP=* USER=* USER-HOST=internal HOST=internal 			//All programs started by hosts within the SAP system can be started on all hosts in the system.
```
```
Example of a REGINFO file in new syntax
———————————————————————————————————————
#VERSION=2
P TP=cpict4 HOST=10.18.210.140					//Program cpict4 is allowed to be registered if it arrives from the host with address 10.18.210.140.
D TP=* HOST=10.18.210.140					//All other programs from host 10.18.210.140 are not allowed to be registered.
P TP=cpict2 ACCESS=ld8060,localhost CANCEL=ld8060,localhost     //Program cpict2 is allowed to be registered, but can only be run and stopped on the local host or hostld8060.
P TP=cpict4							//Program cpict4 is allowed to be registered by any host.
P TP=* USER=* HOST=internal					//Programs within the system are allowed to register.
```

<i/> 1.8 - Review the SAP logging strategies / Audit trails</i>
```
Tracing a Transaction
—————————————————————
> SE30 ABAP/4 Runtime Analysis
> ST01 System Trace
> STAT User Activity at UNIX Level (this transaction is very slow)

LOGS in SAP (programme RDDPRCHK)
————————————————————————————————
> Existence de la mise en oeuvre de journaux sur les tables 
> lancer SA38 puis utiliser le programme RDDPRCHK et paramètre REC / Client pour les tables mandant-dépendantes
  et preuve de leur exploitation.
```

<i/> 1.9 - Review the security level of the IT Infrastructure supporting the SAP ERP environment</i>
> Check that the IT infrastructure and network supporting the SAP ERP environment are properly configured to secure communications and operations.
```
> Firewall rules are implemented to restrict network access to the SAP ERP environment (i.e., application layer, server layer, database layer, etc.)
> Patching and hardening of:
  + the servers (e.g., SUSE Linux) supporting the SAP ERP environment
  + the databases (e.g., SAP Hana db, Oracle db) supporting the SAP ERP environment
  + the laptops and/or Citrix portal used by SAP users to log into SAP GUI client (if used)
> …
```
------------------

### 2. SAP User and Access Management Review

<i/> 2.1 - Types of users in SAP </i>
> There are five types of users in SAP (useful link: https://www.stechies.com/type-of-users-in-sap/)
```
Dialog users (A)
———————————————— 
A normal dialog user is used for all logon types by exactly one person. This is used to logon using SAP GUI.
During a dialog logon, the system checks for expired/initial passwords.
The user can change his or her own password. Multiple dialog logons are checked and, if appropriate, logged.
These users are used for carrying out normal transactions. 
This is an interactive type of logon. 
The initial multiple logons are 6. 
They are set according to companies policy.

System Users (B)
————————————————
These are non interactive users. They are used for background processing and internal communication in the
system (such as RFC users for ALE, Workflow, TMS, and CUA). 
Their passwords cannot be changed by the end users. Only the user administrator can change their passwords. 
Multiple logon is permitted in these type of users. Dialog logon is not possible for these type of users.

Communication Users (C)
———————————————————————
Used for dialog-free communication between systems. 
It is not possible to use this type of user for a dialog logon. 
Their passwords are valid for certain period of time so they expire. The users have option to change their own passwords.

Service User (S)
————————————————
Dialog user available to a larger, anonymous group of users. 
The system does not check for expired/initial passwords during logon. 
Only the user administrator can change the passwords. Generally, highly restricted authorizations are given to this type of users.

Reference User (L)
——————————————————
A reference user is, like the service user, a general non-person-related user. 
Dialog logon is not possible with this kind of user. 
A reference user is used only to assign additional authorizations. 
To assign a reference user to a dialog user, specify it when maintaining the dialog user on the Roles tab page.
```

<i/> 2.2 - Review who has access (and with which permissions) to the following list of powerful SAP transactions </i>
> Option 1 - The SUIM transaction can be used for user information system and includes options to view roles, authorizations, and transactions associated with roles.

> Option 2 - The transactions PFCG can be used to view the roles and their associated transactions. By entering the role name, you can see all the transactions that are granted to that role, along with any associated authorization objects.

> Option 3 - Extract and cross-check the content of the following SAP tables: "AGR_1251" (it contains roles and authorization objects), "AGR_1252" (it contains roles and associated transactions), "USR04" and "AGR_USERS" (they both allow to list the accounts member of roles) 
```
List of powerful or sensitive SAP transactions
===============================================
> DBxx  			– Database related transactions
> SCC4, SCC5 			- Client administration
> SE01, SE10 			- CTS / TMS commands
> SE38 				– ABAP Editor  (display, edit, execute ABAP source code)
> SA38				– Only allows ABAP source code execution
> SE93				– Maintains transactions (ex. create or copy a TCODE)
> SM01 				- Lock / unlock transactions
> SM12				– Lock entries
> SM30, SM31			– Table Maintenance (can be used to display and update table data)
> SE11, SE12, SE13, SE14 	- Table structure maintenance
> SE14				- The database utility is the interface between the ABAP Dictionary and the relational database underlying the R/3 System.
				  It allows you to edit (create, delete and adjust to changes to their definition in the ABAP Dictionary) database objects
				  derived from objects of the ABAP Dictionary.
> SE15				– Data Dictionary
> ST04				- Database performance monitor (allow to send SQL request to the database)
> SM32				– Updates Table USR40 with invalid passwords
> SM3 				– Displays and deletes processing job logs
> SM36/SM37			– Schedule Background Job 
> SM49				– Execute external operating system commands
> SM52				– Execute operating system commands
> SM59				– Maintain Remote Function Calls destination definitions
> SM69				– Maintain external commands
> SP01				- Administer print spools
> PFCG				- Role Maintenance (PFCG) can be used to create role and user like SU01
> SU01         	 		- Maintain users, Security Administration transactions (create/delete/lock/unlock user account, change password etc.)
> SU02     			- Allocate authorizations to a profile. Maintain SAP Authorization Profiles.     
				  The transaction code SU02 can be use to manually edit SAP profiles. 
				  As notification from the initial screen, SAP has recommended to not use this transaction any longer
				  for profile and user administration.
> SU10				- User MAss Maintenance (ex. Lock and Unlock user account, Change the password of a user?)
				- Delete/add a profile for all users
> SU03n
> SU03     			- Maintenance of Authorizations 
> SU53     			- Evaluate Authorization Check
> AL11				- Display all the SAP Directories and files stored on the underlying OS server 
> Program/report "RPCIFU01" 	- Display OS files
> Program/report "RPCIFU03" 	- Download OS files	
> Program/report "RSBDCOS0" 	- Execute OS commands
> CG3Z or GUI_upload and CG3Y or GUI_download  - Upload / download files to SAP systems (underlying OS server)
> SXDA, SXDB			- Data Transfer Workbench 
> SXDA_TOOLS    		- DX Workbench: tools  
> SU56				- User Authorization Buffer
> SM01				- Can be used to block specific transactions and to list all transactions
> RSUDO 			- idem SUDO mais pour SAP
> RSRT 				- Query monitor
> SCMP 				- Table/View Comparaison
> SQVI				- Table Quickviewer
> SUIM				- select USER and then "specific transactions" to see the list of users having access to specifics transactions
	
> OS04				- Local System Configuration
> OS05				- Remote System Configuration
> OS06				- Local Operating System Activity
> OS07				- Remote Operating System Activity

> SM13				- Administrate Update Records
> SM1				- Update Program Administration
> SM20				- Security Audit Log Assessment
> SM21				- Online System Log Analysis
	
> TU02				- Parameter changes
	
> SE06				- Set Up Transport Organizer
> STMS				- Transport Management System
> SCC4				- (customize it to ztcode) - Administrationdes mandants
<SNIP>
```
<i/> 2.3 - Focus on the SAP transactions that allow to display the tables containing the SAP password hashes </i>
> Multiple SAP transactions can be used to display the table USR02 and/or the view VUSR02_PWD that contain the local password hashes.
```
> SAP Quick Viewer : SQVI 
> SAP Standard query : SQ01 
> ST04 / DBACOCKPIT
> SE16
> SE16n
> SCMP  (View / Table Comparison)
> SM30
> SM31
> ...
```
<i/> 2.4 - Weak parameter transactions </i>
```
Parameter transactions execute an existing transaction delivering pre-defined screen input.
To determine all unsafe parameter transactions for SE16, SM30… you need to search for PARAMs matching "/N<TCD>" (e.g. "/NSM30*") in the table TSTCP.
=> The presence of "/*" indicates that the first screen is skipped and thus the view name cannot be overridden.
=> The presence of "/N<TCD>" (e.g. "/NSM30*") indicates that the first screen is not skipped and thus the pre-filled view name can be overridden (leaving the choice of the actual view name up to the user).
Sources:
- https://www.daniel-berlin.de/security/sap-sec/table-authorizations/
- https://www.daniel-berlin.de/security/sap-sec/weak-parameter-transactions-sap/
```

-------------------

### 3. Risks of having the ABAP Debugger enabled in production environment

> One of the major risks in SAP is its powerful debugging environment with the ability to stop each program and enter debugging mode while the program continues running (including the ability to change values at run time). 
The debugger allows bypassing certain controls (like authorization checks) and changing the system return-code (SY-SUBRC) for authorizations checks from Failed (4) to Succeeded (0).
This could allow a hacker to either change an account number while running a payment program or change a report selection value or change the password of SAP privileged account.


<i/> SAP privilege escalation attack - Bypass security controls with the ABAP Debugger </i>
```
+ If the ABAP Debugger is enabled in production, a malevolent person having read-only access to SAP tables with transactions such as SE16 or SE16n could bypass controls (authorizations checks) and modify data to perform a privilege escalation attack and/or a financial fraud. 
   > How-to: 
      https://sapbasissolutions.wordpress.com/2017/10/12/how-to-edit-sap-tables-without-coding-or-debugging/

+ If the ABAP Debugger is enabled in production, a malevolent person could bypass security controls to get unauthorized access to certain SAP transactions (goal: perform a privilege escalation attack or a financial fraud). 
   > How-to: 
      https://www.erpworkbench.com/sap-security/bypass/bypass-tcode.htm
      https://blogs.sap.com/2013/09/06/abap-tip-and-trick-to-break-tcode-access-to-not-so-authorized-tcodes/
```

<i/> Defense tips & Recommendations </i>
```
+ Remove debugging authorizations from all users while granting privileged access to users that really have to enter the debugging environment.

+ Define debugging as a sensitive authorization and receive an alert for when someone is granted such authorization.
   > The S_DEVELOP authorization object controls access to the debugger. 
   > You can locate the roles that contain the S_DEVELOP authorization object using the SUIM report "Roles by Authorisation Values".
   > You can locate the Users which have the S_DEVELOP authorization object using the SUIM report "Users by Authorisation Values".

+ Monitor users and their activities in the debugging environment.
   > If a user replace variables (with the debugging mode) it creates a system log message; check SM21 !

+ Eliminate authorization to change values in the debugger, and instead permit only display options.
```

------------
### 4. Sensitive Information Disclosure from SAP Spool

> One of the overlooked backdoors for getting valuable and sensitive data is the SAP spool. When a user/job prints in SAP, the output is first collected in the SAP spool (called Spool Request) and only then sent to the physical printer. 
Many times the spool request is not deleted from the spool (for a very long time), even after the content is printed. Clearly, this turns the SAP spool into an excellent source for hackers to find information about money transfer slips, monthly pay-slips, check printouts, purchase orders and more.
Furthermore, most users have access to the SAP spool (directly via T-Code SP01 or indirectly via T-Code SM37), and most organizations enable unlimited access to the spool items, including the options to view, download and re-print the content.

<i/> Defense tips & Recommendations </i>
```
+ Inspect which users access SAP spool items, especially those that were not created by them.
+ Define sensitive spool items by criteria and alert when they are accessed.
```

--------------
### 5. Development Kits and Transactions
```
SAP Developper/ABAP/Workbench
—————————————————————————————
> SE36 ABAP/4: Logical Databases
> SE37 ABAP/4 Function Modules
> SE38 ABAP/4 Program Development
> SE80 ABAP/4 Development Workbench
> SE81 SAP Application Hierarchy
> SE82 Customer Application Hierarchy
> SE84 ABAP/4 Repository Information System
> SE86 ABAP/4 Repository Information System 
```
```
kit de développement RFC
—————————————————————————
Le kit de développement RFC permet de créer / modifier / supprimer une interface de type RFC (Remote Function Call). 
Il est installé en standard par SAP.
La gestion des liaisons RFC est réservée à un groupe restreint d’administrateurs clairement identifiés. La liste est tenue à jour.
> suppression du kit de développement RFC (SDK « RFCSDK ») sur l’environnement de production.
```
```
Remove developer keys from productive systems
—————————————————————————————————————————————
Many auditors check on productive SAP systems if any developer keys exist (in table DEVACCESS). 
If there are any, this might become a finding that can easily avoid (… although the system is properly protected against changes in SCC4 and SE03).
```

-------------------

### 6. SAP Hana Database Security Configuration Review

<i/> 6.1 - List of useful SQL queries to extract the database configuration (e.g. list of users, roles, privileges, password policy, logs) </i>
```
'SELECT * FROM SYS.USERS LIMIT 500'
'SELECT * FROM SYS.USERS_PARAMETERS LIMIT 500'
'SELECT * FROM SYS.M_PASSWORD_POLICY'
'SELECT * FROM SYS.P_CREDENTIALS_'
'SELECT * FROM SYS.M_SECURESTORE'
'SELECT * FROM SYS.SCHEMAS LIMIT 500'
'SELECT * FROM SYS.ROLES LIMIT 500'
'SELECT * FROM SYS.PRIVILEGES’
'SELECT * FROM SYS.PROCEDURES'
'SELECT * FROM SYS.P_CREDENTIALS_' (not authorized)
'SELECT * FROM SYS.TABLES LIMIT 500'
'SELECT * FROM SYS.AUDIT_ACTIONS LIMIT 500'
'SELECT * FROM SYS.M_CONNECTIONS'
'SELECT * FROM SYS.M_DATABASE'
'SELECT * FROM SYS.M_HOST_INFORMATION'
'SELECT * FROM SYS.M_INIFILE_CONTENTS' 
'SELECT * FROM usr02;'
```

<i/> 6.2 - How to log into the database to extract the configuration </i>
```
> [Option 1] The SAP HANA configuration can be collected using a “SAP Basis” account with the ‘ST04’ and ‘DBxx’ transactions

> [Option 2] Use SAP HANA HDBSQL to execute SQL commands at OS level.

	+ HDBSQL is a command line tool for executing commands on SAP HANA databases.
          SAP HANA HDBSQL is also used to automate the HANA Database backups using cron scripts. 
	+ Requirement: You want to access SQL prompt using HDBSQL at OS level. 
	+ Prerequisites : You need password of <SID>ADM user and User with HANA database access, in our example we are connecting using SYSTEM.
	+ Steps :
	• Logon to HANA host with <SID>adm user.
	• Once you are logged in as <SID>adm  you can directly execute the hdbsql command , or you can go to following path and execute the hdbsql command.  
	• cd /hana/shared/<SID>/hdbclient 
	• Now execute the command 
	• hdbsql  -n localhost -i 00 -u SYSTEM -p Ina123  

	Once you get the command , enter \s to get the system information you are connected to.
	Exit HDBSQL by entering the command: exit or quit or \q

	You can also log on with user credentials for the secure user store (hdbuserstore) with -U <user_key>. 
	HDBSQL Examples :
	---------------
	> hdbsql  -n localhost -i 00 -u SYSTEM -p Ina123;
	> hdbsql -S DEV -n localhost:30015 -u SYSTEM -p In123 ;
	> hdbsql -n localhost -i 00 -u myuser -p myuserpassword "select * from sys.users";
	> hdbsql -U myUserSecureStore "Select table_name, schema_name from m_tables" ;
	> hdbsql -U SUPER "SELECT * FROM SYS.P_CREDENTIALS_" ;
	> hdbsql -u SYSTEM -n HOSTNAME:34215 -s EEP -sslprovider commoncrypto -sslkeystore $SECUDIR/sapsrv.pse -ssltruststore $SECUDIR/sapsrv.pse "SELECT * FROM SYS.P_CREDENTIALS_" ; 

	Note:
	"A user administrator can exclude users from this password check with the following SQL statement: ALTER USER <user_name> DISABLE PASSWORD LIFETIME.
	 However, this is recommended only for technical users only, not database users that correspond to real people.
	 A user administrator can re-enable the password lifetime check for a user with the following SQL statement: ALTER USER <user_name> ENABLE PASSWORD LIFETIME"
```
------------

## II - SAP Penetration testing 

------------

### 1. How to get unauthorized access to SAP tables and data using SAP transactions

<i/>Access to tables that include sensitive data should be carefully granted and monitored, specifically to inspect who is allowed to see/edit the data and who actually sees/edits it; who is able to use the table in QuickViewer / Data Browser (...) and who actually did; in which views the table is being used and who viewed the data; and finally in which queries the table is used and who performed these queries.</i>
```
There are multiple ways to display & edit tables in SAP
—————————————————————————————————————————————————————————
+ Standard table browsing and maintenance transactions: 
   > SE16 & SE16N (Data Browser), 
   > SE17 (General Table Display)
   > SM30 (Enhanced Table Maintenance Tool)
   > SM31 (Standard Table Maintenance Tool - Old)
+ Proxy-transactions like SPRO (which call the aforementioned ones internally).
+ SAP Query transactions: 
   > SQVI (SAP Quick Viewer), 
   > SQ01 (SAP Standard Query), 
   > SCMP (View / Table Comparison),
+ The ABAP report/program "RK_SE16N" that can be launched via the transaction SA38 (potential only / not tested).
+ The module pool "SAPMSVMA" that can be launched using SE38 (potential only / not tested).
+ Database monitoring tool (ST04).
```
```
Example of tables containing sensitive data
————————————————————————————————————————————
+ Useful "User Master Tables"
   > USR01 - User Master Records
   > USR02 - User IDs and Passwords (includes last logon data)
   > USH02 - password change history
   > VUSR02_PWD - View containing User IDs and Passwords
   > USR40 - Non-permissible password values
   > USR04 - User Master Authorizations
   > USR10 - Authorization Profiles  (i.e. &_SAP_ALL)
   > USR11 - User Master Profiles and Descriptions
   > USR12 - User Master Authorization Values

+ Useful "Authorization Tables"
   > UST04 - User Masters (all Users with profiles)
   > UST10C - User Master: Composite Profiles
   > UST10S - User Master: Simple profiles
   > UST12 - User Master: Authorizations
   > AGR_1250 - Role and. Authorization data.
   > AGR_DEFINE - To See All Roles (Role definition).	

+ Useful « Bank/Payment Tables »
   > T012 - House Banks
   > T012A / B - Allocation payment methods > Bank transfer
   > T012C - Terms for bank transactions
   > T012D - Parameter for DMEs and foreign PM
   > T012E - EDI-compatible house banks / PM
   > T012K - House Bank Accounts
   > T012O - ORBIAN Detail: Bank Accounts, ...
   > BNKA - Bank Master
   > TIBAN - IBAN (International Bank Account Number) 
```

<i/> SAP privilege escalation technique 1 </i>
> Dump SAP password hashes from the table USR02 or the view VUSR02_PWD and crack them with « John The Ripper » 
```
+ Read privilege over the table USR02 or the view VUSR02_PWD  (using SE16/SE16n, SM30, SQVI…) can allow a
  malevolent person to collect the password hashes of the SAP local accounts and then try to crack the passwords
  of SAP privileged accounts using the tool « John The Ripper ».

+ Read privilege over the table USH02 (using for example SE16/SE16n, SM30, SQVI) can allow a malevolent person
  to collect the old password hashes of SAP local accounts, then crack them using John The Ripper and try to guess
  the new one (based on the old password pattern).

Tips for SAP passcode cracking
——————————————————————————————
+ SAP passcode (G format) collected in the USR02 table (for the SAP local account "SAP_ADM"): "55D85A52F82E02FE246E9E505F0D2C9BC82C9E14"

+ Password format to use with the tool « John The Ripper » : 
   > login:login$PASSCODE
   > SAP_ADM:SAP_ADM$55D85A52F82E02FE246E9E505F0D2C9BC82C9E14

+ Command to crack the SAP passwords with the tool « John The Ripper » : 
   > John --session=1 --format=sapg --wordlist=rockyou.txt  <File-containg-password-hashes>
```

<i/> SAP privilege escalation technique 2 </i>
> Edit sensitive tables (e.g. USR02, USR04, USR10, USR11,…) using ST04 or SM30 or SM31
```
+ Edit privilege over the users, authorizations and profiles tables could allow a malevolent person to escalate its privileges via multiple ways.
   For examples:
   > Create a new SAP administrator account (SAP_ALL, SAP_New, SAP Basis profiles)
   > Modify the password hashes of an existing SAP administrator account (e.g. SAP*, DDIC, …)
   > Add his/her account in a powerful group such as SAP_ALL, SAP_New or SAP Basis

+ Edit privilege over sensitive financial tables could allow a malevolent person to commit frauds by modifying suppliers/employees bank account numbers, pay slips and/or money transfers.

+ How to determine who can do table updates in production (should not be permitted)
   > SAP transactions = SM30, SM31 (and also ST04)
   > Object = S_TABU_DIS, (client independent tables also require S_TABU_CLI )
   > Activity = 01, 02
   > "sap_edit"
```

<i/> Defense tips & Recommendations </i>
```
+ Prevent users from being granted sensitive authorizations unless they genuinely need it for performing business tasks. 
   Users should be assigned only the minimum number of Authorizations required to perform their duties.
    > Note: Removing SE16N from S_TCODE (for a particular table), but allowing for instance SA38 or START_REPORT does not necessarily prevent direct table access. 
     It's not a big deal, since table authorizations are checked as usual… but keep in mind: removing the tcodes from S_TCODE has a limited effect unless you also take care of S_TABU_*, S_PROGRAM and S_DEVELOP
    (check SAP Note1012066 for the last one)!

+ Alert when a user:
   > Directly accesses a table (via SE16,..), especially a table which is defined as sensitive.
   > Performs a sensitive query.
   > Is granted a sensitive authorization.

+ Data Dictionary updates in production should not be permitted
   > TC = SE11, SE15, SE16, SE38, SE80
   > Object = S_DEVELOP
   > Activities = 01, 02, 06, 07 	
```

------------
### 2. How to get remote OS commands execution using SAP transactions

<i/>There are several SAP transactions that allow authorized users to execute OS commands on the Windows/Linux server(s) hosting a SAP application/instance and/or a SAP database.
All the OS commands are executed by a local OS account « <SID>adm » which is used to manage the SAP software at the OS layer and which can log into the SAP database with high privileges.
If a malevolent person can execute any commands on the server(s) hosting a SAP application/instance with the « <SID>adm » account, then he/she can take over the entire SAP ERP application and data (OS => Database => Application). </i>

```
[Privesc technique 1]
Execute any OS commands on the server hosting the SAP application/instance using the transaction SA38 and the report "RSBDCOS0"
> Go to transaction SA38 (Execute ABAP program/report)
> Run the report "RSBDCOS0"
> Execute any OS commands 
  - write and run a reverse shell, 
  - add a SSH public key and login to the Linux server, 
  - identify OS or database clear-text passwords stored in config files, scripts or .bash_history
 
+ Defense tips: Disable the CALL ‘SYSTEM’ command setting the profile parameter ‘rdisp/call_system’ to ‘0’.


[Privesc technique 2]
Execute any OS commands on the server hosting the SAP application/instance using the transactions « SM69 + SM49 » or « SM69 + SM36 » or « SM69 + SM37 » 
> Go to SM69 (Maintain external OS commands)
> Then create a new external command or edit an existing one
> Then set and save the OS command that you want to run
> Finally execute it using either:
  - SM49 (Execute external OS commands)
  or 
  - SM36  (Simple job selection/scheduler) 
  or 
  - SM37 (Extended job selection/scheduler)

+ Useful links: https://blogs.sap.com/2013/10/29/secure-execution-of-os-commands-by-abap-programs/


[Privesc technique 3]
Execute pre-defined/limited OS commands on the server hosting the SAP application/instance using the transactions SM49 or SM36 or SM37 
Note: In some cases by using the transactions CG3Z (File upload), CG3Y (File upload) and AL11 (SAP OS Directory and file browser) in addition to either SM49 or SM36 or SM37 it is possible to execute any OS commands.
For example, if one of the pre-defined or customized OS commands available is to execute a script or a binary, then the following attack scenario is possible:
> Go to CG3Y (File download)
> Then select and download the script (or binary) that you are allow to execute
> Go to CG3Z (File upload)
> Select and upload/overwrite a malicious script (or binary) on the Windows/Linux server supporting the SAP application/instance 
> Then execute it using either:
  - SM49  (Execute external OS commands)
  or 
  - SM36  (Simple job selection/scheduler) 
  or 
  - SM37  (Extended job selection/scheduler)
> Finally use CG3Z to replace your malicious script (or binary) by the legitimate one.


[Privesc technique 4]
Execute any OS commands on the server hosting the SAP application/instance using the transaction(s) SE38 or « SE38 + SA38 » or « SE38 + SM36 » or « SE38 + SM37 » 
   > Go to SE38 (ABAP editor - create/edit/run ABAP program)
   > Create a new ABAP program (but you will need a developer key if you don't have a "developer" account)
   > Then execute it using either:
       SE38  (ABAP editor - create/edit/run ABAP program)
       or
       SA38  (Display/Execute ABAP program/report)
       or 
       SM36  (Simple job selection/scheduler) 
       or 
       SM37 (Extended job selection/scheduler)


[Privesc technique 5]
Upload a backdoor on the server hosting the SAP application/instance using the transaction CG3Z (File upload)
   > Use CG3Z to overwrite a legitimate script (or binary) with a malicious one that will be more-likely executed later by a legitimate IT admin or a scheduled batch.


[Privesc technique 6]
Execute any OS commands on the server hosting the SAP database using the transaction ST04 (remote OS command execution using Oracle or MSSQL database’s stored procedures)
```

<i/> SAP privilege escalation attack using remote OS commands </i>
> Using one or several of the methods described above perform the following attack:
```
+ Step 1. Get an interactive session on the Windows/Linux server(s) hosting a SAP application/instance and/or a SAP database with the « <SID>adm » account.
   > Write and run a reverse shell (e.g. PowerShell, Python, Perl, Bash)
      OR
   > Add a SSH public key and then log into the Linux server, 
      OR
   > Identify privileged OS or database clear-text passwords stored in config files, scripts or logs (e.g. .bash_history) and then log into the server, 

+ Step 2.  Login to the SAP database (privileged access)

+ Step 3.  Steal and/or edit sensitive data stored in the SAP database to commit a fraud (for instance, modify bank accounts to receive fund transfers/payments)

+ Step 3.bis  Edit SAP tables to add a new SAP user with SAP_ALL privileges and then use this new account to commit fraud.
```

<i/> Other / Notes </i>
```
RSRFCCHECK
——————————
Permet de lister les RFC (sm59) pour lesquels un mot de passe est sauvegarder 

Scanning files content in AL11 
———————————————————————————————
To start this functionality you can press Shift+F1 and a popup will show. Then you can inform which expression you would like to search.
Simply execute AL11 and then execute /NSU53 immediately afterwards. A report of all authorisations checked will then be displayed.

Deleting a file (needs AL11 + SE37)
———————————————————————————————————
Step 1: Go to Transaction SE37, enter Function module name EPS_DELETE_FILE and click on execute button.
Step 2: Then, enter the File name in the FILE_NAME and the directory path (Excluding the file name) in the DIR_NAME and execute
Step 3: Finally use the AL11 transaction to check that the file has been deleted.

http://quelquepart.biz/article26/cure-de-rajeunissement-pour-al11
```

-------------------

### 3. Bypassing security controls with the ABAP Debugger

<i/> SAP privilege escalation attack - Bypass security controls with the ABAP Debugger </i>
```
+ If the ABAP Debugger is enabled in production, an attacker having read-only access to SAP tables with transactions such as SE16 or SE16n could bypass controls (authorizations checks) and modify data to perform a privilege escalation attack. 
   > How-to: 
      https://sapbasissolutions.wordpress.com/2017/10/12/how-to-edit-sap-tables-without-coding-or-debugging/

+ If the ABAP Debugger is enabled in production, an attacker could bypass security controls to get unauthorized access to certain SAP transactions and perform a privilege escalation attack.
   > How-to: 
      https://www.erpworkbench.com/sap-security/bypass/bypass-tcode.htm
      https://blogs.sap.com/2013/09/06/abap-tip-and-trick-to-break-tcode-access-to-not-so-authorized-tcodes/
```

-------------------

### 4. SAP penetration testing using NMAP and the Metasploit framework

<i/> 4.1 - SAP Discovery using NMAP (network port scanner - https://nmap.org) </i>
```
> root@kali-linux$ nmap -sS -sV -v -p- 10.13.34.12
	<SNIP>
	Nmap scan report for 10.13.34.12
	<SNIP>
	PORT      STATE SERVICE         VERSION
	1128/tcp  open  soap            gSOAP 2.7
	3201/tcp  open  cpq-tasksmart?
	3299/tcp  open  saprouter?
	3301/tcp  open  unknown
	3901/tcp  open  nimsh?
	4901/tcp  open  sybase-adaptive Sybase Adaptive Server
	4902/tcp  open  sybase-backup   Sybase Backup Server
	4903/tcp  open  unknown
	8101/tcp  open  http            SAP Message Server httpd release 745
	30101/tcp open  unknown
	30102/tcp open  unknown
	30103/tcp open  unknown
	30104/tcp open  unknown
	30107/tcp open  unknown
	30108/tcp open  unknown
	30111/tcp open  http            BaseHTTPServer 0.3 (Python 2.7.10)
	30116/tcp open  unknown
	40000/tcp open  safetynetp?
	40001/tcp open  unknown
	40002/tcp open  unknown
	40080/tcp open  http            SAP Internet Graphics Server httpd
	46287/tcp open  status          1 (RPC #100024)
	50000/tcp open  http            SAP WebDispatcher
	50001/tcp open  ssl/http        SAP WebDispatcher
	50004/tcp open  unknown
	50007/tcp open  unknown
	50013/tcp open  soap            gSOAP 2.7
	50014/tcp open  ssl/soap        gSOAP 2.7
	50020/tcp open  unknown
	50113/tcp open  soap            gSOAP 2.7
	50114/tcp open  ssl/soap        gSOAP 2.7


> root@kali-linux$ nmap -sV -p 80 --script http-sap-netweaver-leak 10.13.34.10

	PORT    STATE SERVICE REASON
	443/tcp open  https   syn-ack
	| http-sap-netweaver-leak:
	|   VULNERABLE:
	|   Anonymous access to SAP Netweaver Portal
	|     State: VULNERABLE (Exploitable)
	|             SAP Netweaver Portal with the Knowledge Management Unit allows attackers to obtain system information
	|             including file system structure, LDAP users, emails and other information.
	|
	|     Disclosure date: 2018-02-1
	|     Check results:
	|       Visit /irj/go/km/navigation?Uri=/ to access this SAP instance.
	|     Extra information:
	|       &#x7e;system
	|       discussiongroups
	|       documents
	|       Entry&#x20;Points
	|       etc
	|       Reporting
	|     References:
	|_      https://help.sap.com/saphelp_nw73ehp1/helpdata/en/4a/5c004250995a6ae10000000a42189b/frameset.htm
```

<i/> 4.2 - SAP discovery using NMAP custom probes for a better detection of SAP services (https://github.com/gelim/nmap-erpscan) </i>
```
=> https://github.com/gelim/nmap-erpscan/blob/master/sap_ports.py

> root@kali-linux$ nmap -p $(sap_ports.py) 10.3.3.7 -sV --open
	<SNIP>
	Not shown: 4496 closed ports
	PORT      STATE SERVICE         VERSION
	1128/tcp  open  saphostcontrol  SAPHostControl
	3201/tcp  open  sapjavaenq      SAP Enqueue Server
	3301/tcp  open  sapgateway      SAP Gateway
	3901/tcp  open  sapmsgserver    SAP Message Server
	8101/tcp  open  sapms           SAP Message Server httpd release 745 (SID J45)
	50000/tcp open  sapnetweawer2   SAP NetWeaver Application Server (Kernel version 7.45, Java version 7.50)
	50004/tcp open  sapjavap4       SAP JAVA P4 (Potential internal IP 10.3.3.7)
	50007/tcp open  tcpwrapped
	50013/tcp open  sapstartservice SAP Maganement Console (SID J45, NR 00)
	50014/tcp open  tcpwrapped
	50020/tcp open  sapjoin         SAP Java Cluster Join Service
	50021/tcp open  jdwp            Java Debug Wire Protocol (Reference Implementation) version 1.8 1.8.0_51
	50113/tcp open  sapstartservice SAP Maganement Console (SID J45, NR 01)
	50114/tcp open  tcpwrapped
	Service Info: Host: java745
 ```

<i/> 4.3 - SAP discovery using the Metasploit module 'sap_service_discovery' (https://www.metasploit.com) </i>
```
Module to perform network scans against SAP platforms, which can be found under 'modules/auxiliary/scanner/sap/sap_service_discovery.rb': 
msf  > use auxiliary/scanner/sap/sap_service_discovery.
msf  > set RHOST 192.168.1.149
msf  > exploit
```

<i/> 4.4 - SAP Router </i>
```
Module to launch a port scanner through a SAProuter. 
The module is available on 'modules/auxiliary/scanner/sap/sap_router_portscanner.rb' and allows two types of working modes: 
* SAP_PROTO: Allows port scanning when S(ecure) entries are set in the SAProuter ACL configuration. 
* TCP: Allows port scanning when P(ermit) entries are set in the SAProuter ACL configuration.

In order to ping the ICF component from the exterior and get basic information about it, the unauthenticated /sap/public/ info service
(ICF) can be used if enabled, and that’s just what the auxiliary/scanner/sap/sap_icf_public_info.rb 
> http://IP-address:8042/sap/public/info

Discovering ICF services with the mentioned module is as easy as shown below: 
msf > use auxiliary/scanner/sap/sap_icm_urlscan
msf auxiliary(sap_icm_urlscan) > show options
```

<i/> 4.5 - Attacking the SOAP RFC with Metasploit (e.g.password brute-force, remote OS command execution) </i>
```
When enabled, this service allows remote execution of ABAP programs and functions via HTTP SOAP requests. 
This RFC calling mechanism is protected by HTTP Basic headers (valid SAP credentials are needed), and communications encryption is provided
only when HTTPS is enabled. 

Module 	Description 
auxiliary/scanner/sap/sap_soap_ rfc_brute_login.rb 	
> Attempts to brute force valid SAP credentials to access the SOAP interface via a call to the RFC_PING function.
  Basic HTTP authentication is used for brute forcing. 

auxiliary/scanner/sap/sap_soap_ rfc_system_info.rb 	
> Attempts to use the RFC_SYSTEM_INFO function to obtain different information about the remote system such as operating system, hostname,
  IP addresses, time zone, etc. Valid SAP credentials are required. 

auxiliary/scanner/sap/sap_soap_ rfc_ping.rb 	
> Attempts to use the RFC_PING function to test connectivity with the remote endpoint. Valid SAP credentials are required. 

auxiliary/scanner/sap/sap_soap_ rfc_eps_get_directory_listing.rb 	
> Attempts to use the EPS_GET_DIRECTORY_LISTING function to disclose if a remote directory exists ( le system level) and the number of entries
  into it. Valid SAP credentials are required. This module also can be used to launch an SMB Relay Attack. 

auxiliary/scanner/sap/sap_soap_ rfc_p _check_os_file_existence.rb 	
> Attempts to use the PFL_CHECK_OS_FILE_EXISTENCE function to check if a le exists in the remote le system.
   Valid SAP credentials are required. This module also can be used to launch an SMB Relay Attack. 

auxiliary/scanner/sap/sap_soap_ th_saprel_disclosure.rb 	
> Attempts to use the RFC_READ_TABLE function to dump database data from the SAP system.
  Valid SAP credentials are required. 

auxiliary/scanner/sap/sap_soap_ rfc_read_table.rb 	
> Attempts to use the TH_SAPREL function to disclose information about the remote SAP system such as OS kernel version, database version,
  or SAP version and patch level. Valid SAP credentials are required. 

auxiliary/scanner/sap/sap_soap_ rfc_rzl_read_dir.rb
> Attempts to use the RZL_READ_DIR_LOCAL function to enumerate directory contents on the remote system.
  Valid SAP credentials are required. This module also can be used to launch an SMB Relay Attack. 

auxiliary/scanner/sap/sap_soap_ rfc_susr_rfc_user_interface.rb 	
> Attempts to use the SUSR_RFC_USER_INTERFACE function to create a remote SAP user.
  Valid SAP credentials are required. 

auxiliary/scanner/sap/sap_soap_ bapi_user_create1.rb 	
> Attempts to use the BAPI_USER_CREATE1 function to create or modify a remote SAP user.
  Valid SAP credentials are required. 

auxiliary/scanner/sap/sap_soap_ rfc_sxpg_call_system_exec.rb 
> Attempts to use the SXPG_CALL_SYSTEM function to execute valid SM69 transaction commands in remote systems.
  Valid SAP credentials are required. 

auxiliary/scanner/sap/sap_soap_ rfc_sxpg_command_exec.rb 
> Attempts to use the SXPG_COMMAND_EXECUTE function to execute valid SM69 transaction commands in the remote system.
  Valid SAP credentials are required. 

auxiliary/scanner/sap/sap_soap_ rfc_dbmcli_sxpg_call_system_ command_exec.rb 
> Attempts to attack the SXPG_CALL_SYSTEM function to inject and execute arbitrary OS commands through the SM69 DBMCLI command.
  Valid SAP credentials are required. For more information about the DBMCLI injection, see this blog from @ nmonkee. 

auxiliary/scanner/sap/sap_soap_ rfc_dbmcli_sxpg_command_exec.rb
 > Attempts to attack the SXPG_COMMAND_EXECUTE function to inject and execute arbitrary OS commands through the SM69 DBMCLI command.
   Valid SAP credentials are required. For more information about the DBMCLI injection, see this blog from @ nmonkee.  

exploits/multi/sap/sap_soap_rfc_ sxpg_call_system_exec.rb 
> Attempts to attack command injection issues on SXPG_CALL_ SYSTEM to externally execute a Metasploit payload on the remote system.
  Valid SAP credentials are required. 

exploits/multi/sap/sap_soap_rfc_ sxpg_command_exec.rb 
> Attempts to attack command injection issues on SXPG_ COMMAND_EXECUTE to externally execute a Metasploit payload on the remote system.
  Valid SAP credentials are required. 
```

<i/> 4.6 - SMB Relay attacks using Metasploit </i>
```
There is also an interesting attack that can target different SAP functions and is reachable via the SOAP RFC or other components
such as those in the J2EE engine—more about that later. 
While handling names, a lot of functions are vulnerable to SMB Relay Attacks. 
These attacks send an UNC path pointing to a server capturing SMB hashes, which can be disclosed when the vulnerable component
tries to access it. 

> Some SMB Relay Attack attacks, both unauthenticated and authenticated, have been collected by @nmonkee in an auxiliary module located
  at /auxiliary/scanner/sap/sap_smb_relay.rb. 
> Module to run to capture the SMB Hashs (LMhash and NTHash): auxiliary/server/capture/smb module capturing SMB hashes 
```

<i/> 4.7 - SAP Web interface password brute-force using Metasploit </i>
```
Launch password brute-force attacks against the Web GUI with the Metasploit module "auxiliary/scanner/sap/sap_web_gui_brute_login.rb"

msf > use auxiliary/scanner/sap/sap_web_gui_brute_login
msf auxiliary(sap_web_gui_brute_login) > show options
<SNIP>
msf auxiliary(sap_web_gui_brute_login) > set RHOSTS 192.168.172.179
msf auxiliary(sap_web_gui_brute_login) > set RPORT 8042
msf auxiliary(sap_web_gui_brute_login) > run
<SNIP>
[SAP] Credentials
=================
   host             port  client  user  pass
   ----             ----  ------  ----  ----
   192.168.172.179  8042  001     SAP*  06071992
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(sap_web_gui_brute_login)
```

<i/> 4.8 - SAP Portal - J2EE engine exploits </i>
```
Alexander Polyakov and Dmitry Chastuhin presented work on the J2EE engine (SAPocalypse NOW: Crushing SAP’s J2EE Engine and Breaking SAP Portal). 
Attacks from the above presentations have been published as Metasploit modules: 
+ @nmonkee implemented the VERB tampering bypass (use HEAD as opposed to GET) to attack the ConfigServlet and create an operating system account. 
   > The module can be found at modules/auxiliary/scanner/sap/sap_ctc_verb_ tampering_user_mgmt.rb.  
+ Andras Kabai implemented the ConfigServlet attack to execute arbitrary commands without authentication. 
   > The module can be found at modules/exploits/windows/http/sap_con gservlet_exec_no_auth.rb.  
```

<i/> 4.9 - Attacking the SAP Management Console with Metasploit </i>
```
Attack of the SAP MC SOAP interface to retrieve a lot of interesting information about an SAP system :

modules/auxiliary/scanner/sap/sap_mgmt_con_abaplog.rb 
> Attempts to extract the ABAP syslog. 

modules/auxiliary/scanner/sap/sap_mgmt_con_brute_login.rb 
> Attempts to brute force the credentials for the SAP Management Console. 

modules/auxiliary/scanner/sap/sap_mgmt_con_extractusers.rb 
> Attempts to extract users from the ABAP syslog. 

modules/auxiliary/scanner/sap/sap_mgmt_con_getaccesspoints.rb 
> Attempts to get a list of listening services within the SAP system. 

modules/auxiliary/scanner/sap/sap_mgmt_con_getenv.rb 
> Attempts to get SAP environment settings. 

modules/auxiliary/scanner/sap/sap_mgmt_con_getlogfiles.rb 
> Attempts to download log les and developer trace les. 

modules/auxiliary/scanner/sap/sap_mgmt_con_getprocesslist.rb 
> Attempts to get a list of SAP processes. 

modules/auxiliary/scanner/sap/sap_mgmt_con_getprocessparameter.
> Attempts to get a list of SAP rb processes, parameters, and configurations. 

modules/auxiliary/scanner/sap/sap_mgmt_con_instanceproperties.rb 
> Attempts to get the instance properties. 

modules/auxiliary/scanner/sap/sap_mgmt_con_listlogfiles.rb 
> Attempts to get a list of available log files and developer trace files. 

modules/auxiliary/scanner/sap/sap_mgmt_con_startpro le.rb
> Attempts to get the SAP startup profile. 

modules/auxiliary/scanner/sap/sap_mgmt_con_version.rb 
> Attempts to get the SAP version. 

modules/exploits/windows/http/sap_mgmt_con_osexec_ payload.rb 
> Attacks the OSExecute functionality on the SAP Management Console to run arbitrary commands and finally a Metasploit payload.
 SAP Management Console credentials are required. 
```

<i/> 4.10 - Exploiting SAPHostControl with Metasploit </i>
```
The component that provides the SOAP endpoint for the SAP Management Console on the TCP port '50013' for the default instance is "startsrv". 

According to the SAP documentation, the executable sapstartsrv runs in host mode for monitoring purposes only.
The interesting thing about this sapstartsrv component is that it’s also listening for SOAP requests. 

The GetDatabaseStatus call was attacked by Michael Jordon in order to get an arbitrary code execution from a command injection.
The exploit for this attack is also available on Metasploit as modules/exploits/windows/http/sap_host_control_cmd_ exec.rb.

It’s worth mentioning that the injection technique inspired @nmonkee when writing the OS command injections for the "SXPG_CALL_SYSTEM_SXPG_CALL_SYSTEM"
 and "SXPG_COMMAND_EXECUTE" RFC SOAP calls
(remember also to check his post for more information about these command injections). 
The GetComputerSystem call was abused by Bruno Morisson to retrieve information related to the remote host without any authentication.
The exploit for this attack is available on modules/auxiliary/scanner/sap/sap_hostctrl_getcomputersystem.rb.
The next screenshot shows the information retrieved: 

msf auxiliary(sap_hostctrl_getcomputersystem) > run
[+] 192.168.172.133:1128 - Information retrieved successfully
[*] 192.168.172.133:1128 - Response stored in /Users/juan/.msf4/loot/20131011090901_default_192.168.172.133_sap.getcomputers_832535.xml
(XML) and /Users/juan/.msf4/loot/20131011090901_default_192.168.172.133_sap.getcomputers_372729.txt (TXT)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(sap_hostctrl_getcomputersystem) > set verbose true
verbose => true
msf auxiliary(sap_hostctrl_getcomputersystem) > run
```	

<i/> 4.11 - SAP NetWeaver Dispatcher </i>
```
The disp+work.exe process is vulnerable to a buffer overflow (CVE-2012-2611) while handling Traces, which can be exploited with the metasploit module modules/exploits/windows/misc/sap_netweaver_dispatcher.rb: 
msf  exploit(sap_netweaver_dispatcher) > use exploit/windows/misc/sap_netweaver_dispatcher
msf  exploit(sap_netweaver_dispatcher) > set RHOST 192.168.1.149
RHOST => 192.168.1.149
msf  exploit(sap_netweaver_dispatcher) > exploit
```
